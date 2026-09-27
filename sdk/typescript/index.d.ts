export type Freshness = {mode:"latest"} | {mode:"snapshot";snapshot_id:string} | {mode:"at_least";barrier_token:string};
export interface Endpoint {hostname:string;port:number;database:string;sslmode:"verify-full"}
export interface Operation {id:string;kind:string;status:"queued"|"running"|"succeeded"|"failed"|"cancelled";attempt:number;workspace_id?:string;error?:{code:string;message:string;retryable:boolean}}
export interface Workspace {id:string;project_id:string;generation:number;task_id:string;desired_state:"running"|"paused"|"deleted";phase:string;expires_at:string;resource_profile:string;baseline_id:string;snapshot_id?:string;endpoint?:Endpoint}
export interface Credential {id:string;workspace_id:string;generation:number;username:string;password:string;endpoint:Endpoint;expires_at:string}
export type Action = {action:"pause"|"resume";expected_generation:number} | {action:"extend_ttl";expected_generation:number;expected_expires_at:string;expires_at:string} | {action:"reset";expected_generation:number;discard_local_changes:true;baseline_id:string;freshness:Freshness};
export interface CreateRequest {baseline_id:string;task_id:string;freshness:Freshness;resource_profile:"small"|"medium";ttl_seconds:number;code_revision?:string}
export interface Baseline {id:string;source_id:string;generation:number;source_epoch:number;kind:"physical_standby"|"logical_writer";privacy_mode:"raw"|"sanitized";state:string;runtime_digest:string;observed_at?:string}
export interface Source {id:string;connector:"physical"|"logical";generation:number;source_epoch:number;status:string;observed_at?:string}
export interface UsageMeasurement {id:string;resource_reference:string;metric:string;amount:string;unit:"bytes";interval_start:string;interval_end:string;dimensions:{kind:"observed_gauge";host_id:string;authority_epoch:string;dataset_guid:string;boot_id:string;elapsed_ns:number;batch_id:string}}
export class PGWSError extends Error {status:number;code:string;retryable:boolean;body:Record<string,unknown>}
export class Client {
 constructor(options:{url:string;projectId:string;token:string;timeout?:number});
 registerSource(endpoint:string,secret:string,key:string,signal?:AbortSignal):Promise<{source_id:string;operation:Operation}>;
 source(sourceId:string,signal?:AbortSignal):Promise<Source>;
 reseedSource(sourceId:string,expectedSourceEpoch:number,key:string,signal?:AbortSignal):Promise<{source_id:string;source_epoch:number;baseline_id:string;generation:number;operation:Operation}>;
 baselines(options?:{cursor?:string;limit?:number;signal?:AbortSignal}):Promise<{items:Baseline[];next_cursor?:string}>;
 usage(options?:{cursor?:string;limit?:number;signal?:AbortSignal}):Promise<{items:UsageMeasurement[];next_cursor?:string;measurement_kind:"observed_gauge"}>;
 barrier(sourceId:string,key:string,signal?:AbortSignal):Promise<{source_id:string;source_epoch:number;barrier_token:string;issued_at:string;expires_at:string}>;
 create(request:CreateRequest,key:string,signal?:AbortSignal):Promise<{workspace:Workspace;operation:Operation}>;
 get(workspaceId:string,signal?:AbortSignal):Promise<Workspace>;
 action(workspaceId:string,request:Action,key:string,signal?:AbortSignal):Promise<Operation>;
 credentials(workspaceId:string,request:{expected_generation:number;role:"owner"|"reader";ttl_seconds:number},key:string,signal?:AbortSignal):Promise<Credential>;
 delete(workspaceId:string,generation:number,key:string,signal?:AbortSignal):Promise<Operation>;
 operation(operationId:string,signal?:AbortSignal):Promise<Operation>;
 wait(operationId:string,options?:{timeout?:number;interval?:number;signal?:AbortSignal}):Promise<Operation>;
}
