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
function delta(before,after){const b=new Map(before.nodes.map(n=>[n.id,n]));const a=new Map(after.nodes.map(n=>[n.id,n]));return {added:after.nodes.filter(n=>!b.has(n.id)).map(n=>n.id),removed:before.nodes.filter(n=>!a.has(n.id)).map(n=>n.id),changed:after.nodes.filter(n=>b.has(n.id)&&b.get(n.id).status!==n.status).map(n=>n.id)}}
const api={project,delta};if(typeof module==='object'&&module.exports)module.exports=api;else root.ChronicleGraph=api;
})(typeof globalThis==='object'?globalThis:this);
