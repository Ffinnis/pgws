import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import {Client, PGWSError} from "./index.mjs";
const id="00000000-0000-4000-8000-000000000001";
async function fixture(t,responses) {
 const requests=[];
 const server=http.createServer((request,response)=>{
  requests.push({url:request.url,key:request.headers["idempotency-key"]});
  const [status,body]=responses.shift();
  response.writeHead(status,status===307?{Location:"/leaked-token"}:{});
  response.end(JSON.stringify(body));
 });
 await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));
 t.after(()=>new Promise(resolve=>server.close(resolve)));
 return {requests,client:new Client({url:`http://127.0.0.1:${server.address().port}`,projectId:id,token:"private-token"})};
}
test("wait preserves terminal API failure",async t=>{
 const {client,requests}=await fixture(t,[[200,{status:"running"}],[200,{status:"failed",error:{code:"SOURCE_LINEAGE_CHANGED",retryable:false}}]]);
 await assert.rejects(client.wait(id,{interval:1}),e=>e instanceof PGWSError&&e.code==="SOURCE_LINEAGE_CHANGED"&&!e.retryable);
 assert.equal(requests.length,2);
});
test("explicit retry retains key; redirects never forward bearer credentials",async t=>{
 const {client,requests}=await fixture(t,[[503,{code:"OPERATION_PENDING",retryable:true}],[200,{barrier_token:"same"}],[307,{}]]);
 await assert.rejects(client.barrier(id,"stable"),e=>e.retryable);
 await client.barrier(id,"stable");
 assert.deepEqual(requests.map(r=>r.key),["stable","stable"]);
 await assert.rejects(client.baselines(),e=>e.status===307);
 assert.equal(requests.length,3);
});
test("aborted waits stop polling",async t=>{
 const {client,requests}=await fixture(t,[[200,{status:"running"}]]);
 const abort=new AbortController();
 const pending=client.wait(id,{interval:10000,signal:abort.signal});
 setTimeout(()=>abort.abort(new Error("cancelled")),30);
 await assert.rejects(pending,/cancelled/);
 assert.equal(requests.length,1);
});
test("reseed keeps the request key and rejects invalid epochs",async t=>{
 const {client,requests}=await fixture(t,[[202,{source_epoch:2}],[202,{source_epoch:2}]]);
 await client.reseedSource(id,1,"reseed-request");
 await client.reseedSource(id,1,"reseed-request");
 assert.deepEqual(requests[0],requests[1]);
 assert.ok(requests[0].url.endsWith(`/sources/${id}/actions`));
 for (const epoch of [0,true,1.5,1e9]) assert.throws(()=>client.reseedSource(id,epoch,"invalid"),TypeError);
 assert.equal(requests.length,2);
});

test("usage preserves decimal amounts and encodes its cursor",async t=>{
 const {client,requests}=await fixture(t,[[200,{items:[{amount:"9007199254740993"}],measurement_kind:"observed_gauge"}]]);
 const result=await client.usage({cursor:"next+/=",limit:2});
 assert.equal(result.items[0].amount,"9007199254740993");
 assert.ok(requests[0].url.endsWith("/usage?limit=2&cursor=next%2B%2F%3D"));
 assert.equal(requests[0].key,undefined);
});
