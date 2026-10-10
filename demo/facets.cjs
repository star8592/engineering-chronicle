// SPDX-License-Identifier: Apache-2.0
(function(root){'use strict';
function summarize(graphs,index){
 if(!graphs.length||!Number.isInteger(index)||index<0||index>=graphs.length)throw Error('视图位置不合法');
 const g=graphs[index],before=index?graphs[index-1]:{nodes:[],edges:[]};
 const key=e=>e.from+'→'+e.to,oldNodes=new Map(before.nodes.map(n=>[n.id,n])),newNodes=new Map(g.nodes.map(n=>[n.id,n]));
 const oldEdges=new Set(before.edges.map(key)),newEdges=new Set(g.edges.map(key));
 const changes={added:g.nodes.filter(n=>!oldNodes.has(n.id)),removed:before.nodes.filter(n=>!newNodes.has(n.id)),changed:g.nodes.filter(n=>oldNodes.has(n.id)&&(oldNodes.get(n.id).fingerprint!==n.fingerprint||oldNodes.get(n.id).status!==n.status)),edgesAdded:g.edges.filter(e=>!oldEdges.has(key(e))),edgesRemoved:before.edges.filter(e=>!newEdges.has(key(e)))};
 const states=[['failed','失败'],['passed','通过'],['observed','观察记录'],['declared','清单声明'],['plain','过程节点']].map(([id,label])=>({id,label,count:g.nodes.filter(n=>(n.status||(n.evidence?'declared':'plain'))===id).length})).filter(s=>s.count);
 const sources=g.nodes.filter(n=>g.edges.some(e=>e.from===n.id)),targets=g.nodes.filter(n=>g.edges.some(e=>e.to===n.id));
 return {graph:g,changes,states,sources,targets,trajectory:graphs.map((x,i)=>({index:i,nodes:x.nodes.length,edges:x.edges.length})),baseline:index?'上一历史位置':'空图（首次快照）'};
}
const api={summarize};if(typeof module==='object'&&module.exports)module.exports=api;else root.ChronicleFacets=api;
})(typeof globalThis==='object'?globalThis:this);
