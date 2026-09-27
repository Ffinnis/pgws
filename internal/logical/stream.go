package logical

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pglogrepl"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"pgws/internal/physical"
)

// Run follows the source until cancellation or the first invalid boundary. It
// never retries past schema/constraint errors and never acknowledges received
// bytes, keepalive positions or a target commit whose outcome is uncertain.
func (c Connector) Run(ctx context.Context) error {
	slot, publication, err := c.names()
	if err != nil {
		return err
	}
	owner, err := c.connect(ctx)
	if err != nil {
		return err
	}
	defer closeSource(owner)
	if err = AcquireSource(ctx, owner, slot); err != nil {
		return err
	}
	if err = c.checkCurrent(ctx, owner, publication); err != nil {
		return err
	}
	confirmed, err := checkSlot(ctx, owner, slot)
	if err != nil {
		return err
	}
	start, err := physical.ParseLSN(confirmed)
	if err != nil {
		return errors.New("invalid source acknowledgement position")
	}
	contract, _ := c.Target.contract()
	var actual, applied, seed string
	if err = c.Target.Pool.QueryRow(ctx, `SELECT contract,applied_lsn::text,seed_lsn::text FROM _pgws_ingestion.checkpoint WHERE singleton`).Scan(&actual, &applied, &seed); err != nil || actual != contract {
		return errors.New("streaming requires a committed consistent seed and matching target")
	}
	appliedLSN, e1 := physical.ParseLSN(applied)
	seedLSN, e2 := physical.ParseLSN(seed)
	if e1 != nil || e2 != nil || seedLSN == 0 || start < seedLSN || start > appliedLSN {
		return errors.New("source acknowledgement and target journal cannot be reconciled")
	}
	if err = c.persistApplied(applied); err != nil {
		return err
	}
	decoder, err := NewDecoder(c.Target.Plan, confirmed)
	if err != nil {
		return err
	}
	repl, err := c.replication(ctx)
	if err != nil {
		return err
	}
	defer repl.Close(context.Background())
	// Names are derived solely from the validated source UUID and epoch.
	err = pglogrepl.StartReplication(ctx, repl, slot, pglogrepl.LSN(start), pglogrepl.StartReplicationOptions{Mode: pglogrepl.LogicalReplication, PluginArgs: []string{"proto_version '1'", "publication_names '" + publication + "'", "messages 'false'"}})
	if err != nil {
		return errors.New("logical stream could not acquire its exclusive slot")
	}
	ack := pglogrepl.LSN(start)
	nextStatus := time.Now().Add(5 * time.Second)
	for ctx.Err() == nil {
		if !time.Now().Before(nextStatus) {
			if err = c.checkCurrent(ctx, owner, publication); err != nil {
				return err
			}
			if _, err = checkSlot(ctx, owner, slot); err != nil {
				return err
			}
			if err = acknowledge(ctx, repl, ack); err != nil {
				return err
			}
			nextStatus = time.Now().Add(5 * time.Second)
		}
		receiveCtx, cancel := context.WithDeadline(ctx, nextStatus)
		message, receiveErr := repl.ReceiveMessage(receiveCtx)
		cancel()
		if receiveErr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if pgconn.Timeout(receiveErr) {
				continue
			}
			return errors.New("logical stream interrupted; resume from the source-confirmed position")
		}
		switch m := message.(type) {
		case *pgproto3.CopyData:
			if len(m.Data) == 0 {
				return errors.New("empty replication envelope")
			}
			switch m.Data[0] {
			case pglogrepl.PrimaryKeepaliveMessageByteID:
				if len(m.Data) != 18 {
					return errors.New("invalid replication keepalive")
				}
				keepalive, e := pglogrepl.ParsePrimaryKeepaliveMessage(m.Data[1:])
				if e != nil {
					return errors.New("invalid replication keepalive")
				}
				if keepalive.ReplyRequested {
					nextStatus = time.Now()
				}
			case pglogrepl.XLogDataByteID:
				if len(m.Data) < 26 {
					return errors.New("invalid replication data envelope")
				}
				data, e := pglogrepl.ParseXLogData(m.Data[1:])
				if e != nil {
					return errors.New("invalid replication data envelope")
				}
				batch, e := decoder.Decode(data.WALData)
				if e != nil {
					return e
				}
				if batch == nil {
					continue
				}
				if err = c.checkCurrent(ctx, owner, publication); err != nil {
					return err
				}
				if _, err = checkSlot(ctx, owner, slot); err != nil {
					return err
				}
				if _, err = c.Target.Apply(ctx, *batch); err != nil {
					return err
				}
				if err = c.persistApplied(batch.EndLSN); err != nil {
					return err
				}
				position, _ := physical.ParseLSN(batch.EndLSN)
				ack = pglogrepl.LSN(position)
				if err = acknowledge(ctx, repl, ack); err != nil {
					return err
				}
				nextStatus = time.Now().Add(5 * time.Second)
			default:
				return errors.New("unsupported replication envelope")
			}
		case *pgproto3.NoticeResponse, *pgproto3.ParameterStatus:
			// Never log server messages: source values may occur in their detail.
		default:
			return errors.New("logical source ended the qualified stream")
		}
	}
	return ctx.Err()
}

func (c Connector) persistApplied(position string) error {
	if c.AfterDurableApply != nil {
		if err := c.AfterDurableApply(position); err != nil {
			return errors.New("durable logical progress receipt was not persisted; source ACK withheld")
		}
	}
	return nil
}

func (c Connector) checkCurrent(ctx context.Context, conn *pgx.Conn, publication string) error {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return errors.New("source validation transaction unavailable")
	}
	defer tx.Rollback(context.Background())
	if err = c.checkSchema(ctx, tx); err != nil {
		return err
	}
	return c.checkPublication(ctx, conn, publication)
}

func acknowledge(ctx context.Context, repl *pgconn.PgConn, position pglogrepl.LSN) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	deadline := time.Now().Add(3 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := repl.Conn().SetWriteDeadline(deadline); err != nil {
		return errors.New("source acknowledgement deadline unavailable")
	}
	err := pglogrepl.SendStandbyStatusUpdate(ctx, repl, pglogrepl.StandbyStatusUpdate{WALWritePosition: position, WALFlushPosition: position, WALApplyPosition: position})
	_ = repl.Conn().SetWriteDeadline(time.Time{})
	if err != nil {
		return errors.New("source acknowledgement was not confirmed; durable target replay is required")
	}
	return nil
}
