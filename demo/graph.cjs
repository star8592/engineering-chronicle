// SPDX-License-Identifier: Apache-2.0
(function(root){'use strict';
function project(events,cursor,mode){
 if(!Array.isArray(events)||!events.length||!Number.isInteger(cursor)||cursor<0||cursor>=events.length)throw Error('图投影位置不合法');
 if(mode==='demo'){
 const nodes=[{id:'need',label:'交付目标',detail:'重复事件只入账一次',at:0,event:0,lane:0,col:0},
 {id:'test',label:'原始测试',detail:'失败现场永久保留',at:1,event:1,lane:1,col:0,status:'failed'},
 {id:'decision',label:'修复决策',detail:'原子唯一性检查',at:2,event:2,lane:0,col:1},
 {id:'fix',label:'修复提交',detail:'demo-b02',at:3,event:3,lane:1,col:1},
 {id:'retest',label:'修复后复测',detail:'两项通过',at:4,event:4,lane:1,col:2,status:'passed'},
 {id:'bundle',label:'证据包',detail:'失败与成功同时保留',at:5,event:5,lane:0,col:2}].filter(n=>n.at<=cursor);
 const edges=[{from:'need',to:'test',at:1},{from:'test',to:'decision',at:2},{from:'decision',to:'fix',at:3},{from:'fix',to:'retest',at:4},{from:'retest',to:'bundle',at:5},{from:'test',to:'bundle',at:5,kind:'retained'}].filter(e=>e.at<=cursor);
 return {nodes,edges,scope:'示例证据关系 · 不是实际服务拓扑'};
 }
 // Only visualise observed records. Adjacent positions do not establish causality.
 const start=Math.max(0,cursor-5);const nodes=events.slice(start,cursor+1).map((e,i)=>({id:'record-'+(start+i),label:e.title,detail:e.commit.slice(0,8),at:start+i,event:start+i,lane:i%2,col:Math.floor(i/2),status:e.type==='通过'?'observed':undefined}));
 const edges=nodes.slice(1).map((n,i)=>({from:nodes[i].id,to:n.id,at:n.at,kind:'order'}));
 return {nodes,edges,scope:'真实记录演化 · 虚线仅表示采集展示顺序；架构依赖未采集'};
}
function cargo(snapshot,event){
 const rootManifest=snapshot.manifests.find(m=>m.path==='Cargo.toml');
 const packages=snapshot.manifests.filter(m=>m.parsed.package);const names=new Set(packages.map(m=>m.parsed.package.name));
 const slots={'chronicle-cli':[0,0],'chronicle-verifier':[1,0],'chronicle-core':[0,1],'chronicle-protocol':[1,1]};const nodes=[],edges=[];let external=0;
 for(const m of packages){const name=m.parsed.package.name;const [col,lane]=slots[name]||[0,0];nodes.push({id:name,label:name.replace('chronicle-',''),detail:'模块 · Cargo 清单',event,col,lane,fingerprint:m.sha256,evidence:{commit:snapshot.commit,...m}})}
 for(const m of packages){for(const [dependency,spec] of Object.entries(m.parsed.dependencies||{})){const resolved=typeof spec==='object'&&spec.workspace?rootManifest.parsed.workspace.dependencies[dependency]:spec;const version=typeof resolved==='string'?resolved:resolved?.version;const label=dependency;let id=dependency;
 if(!names.has(dependency)){id='external-'+dependency;if(!nodes.some(n=>n.id===id))nodes.push({id,label,detail:'声明版本 '+(version||'未指定'),event,col:2,lane:external++,fingerprint:JSON.stringify(resolved),evidence:{commit:snapshot.commit,...m}})}
 edges.push({from:m.parsed.package.name,to:id,kind:'dependency',evidence:{commit:snapshot.commit,path:m.path},at:event});}}
 return {nodes,edges,scope:'真实 Cargo 声明依赖 · 仅清单层级，不代表运行调用或完整代码架构'};
}
function delta(before,after){const b=new Map(before.nodes.map(n=>[n.id,n]));const a=new Map(after.nodes.map(n=>[n.id,n]));const key=e=>e.from+'→'+e.to;const be=new Set(before.edges.map(key));const ae=new Set(after.edges.map(key));return {added:after.nodes.filter(n=>!b.has(n.id)).map(n=>n.id),removed:before.nodes.filter(n=>!a.has(n.id)).map(n=>n.id),changed:after.nodes.filter(n=>b.has(n.id)&&(b.get(n.id).status!==n.status||b.get(n.id).fingerprint!==n.fingerprint)).map(n=>n.id),edgesAdded:after.edges.filter(e=>!be.has(key(e))).length,edgesRemoved:before.edges.filter(e=>!ae.has(key(e))).length}}
function neighborhood(g,id){
 if(!g.nodes.some(n=>n.id===id))return null;
 const key=e=>e.from+'→'+e.to;
 function walk(reverse){const seen=new Set([id]),edges=new Set(),queue=[id];for(let i=0;i<queue.length;i++){for(const e of g.edges){if((reverse?e.to:e.from)!==queue[i])continue;edges.add(key(e));const next=reverse?e.from:e.to;if(!seen.has(next)){seen.add(next);queue.push(next)}}}seen.delete(id);return {nodes:[...seen],edges:[...edges]}}
 const dependencies=walk(false),dependents=walk(true);return {id,dependencies,dependents,directDependencies:[...new Set(g.edges.filter(e=>e.from===id&&e.to!==id).map(e=>e.to))],directDependents:[...new Set(g.edges.filter(e=>e.to===id&&e.from!==id).map(e=>e.from))]};
}
const api={project,cargo,delta,neighborhood};if(typeof module==='object'&&module.exports)module.exports=api;else root.ChronicleGraph=api;
})(typeof globalThis==='object'?globalThis:this);
