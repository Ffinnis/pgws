-- Source operations share one monotonic host fence across barrier requests.
ALTER TABLE pgws_control.sources ADD COLUMN host_fencing_token bigint NOT NULL DEFAULT 0 CHECK(host_fencing_token>=0);
