// SPDX-License-Identifier: Apache-2.0
// Bounded, duplicate-key-aware JSON import. Package claims never grant trust.
(function(root){'use strict';
const MAX_BYTES=1048576,MAX_DEPTH=16;
function parseStrict(text){
 if(typeof text!=='string'||new TextEncoder().encode(text).length>MAX_BYTES)throw Error('记录包超过 1 MiB 或不是文本');
 let i=0;const ws=()=>{while(/\s/.test(text[i]||'')&&i<text.length)i++};
 function str(){const start=i++;while(i<text.length){const c=text[i++];if(c==='"'){return JSON.parse(text.slice(start,i))}if(c==='\\')i++;}throw Error('字符串未闭合')}
 function value(depth){if(depth>MAX_DEPTH)throw Error('JSON 嵌套超过 16 层');ws();const c=text[i];if(c==='"')return str();if(c==='{'){i++;ws();const keys=new Set();if(text[i]==='}'){i++;return}for(;;){ws();if(text[i]!=='"')throw Error('对象键必须为字符串');const key=str();if(keys.has(key))throw Error('重复字段：'+key);keys.add(key);ws();if(text[i++]!==':')throw Error('缺少冒号');value(depth+1);ws();const sep=text[i++];if(sep==='}')return;if(sep!==',')throw Error('对象语法错误')}}if(c==='['){i++;ws();if(text[i]===']'){i++;return}for(;;){value(depth+1);ws();const sep=text[i++];if(sep===']')return;if(sep!==',')throw Error('数组语法错误')}}const match=/^(?:null|true|false|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(i));if(!match)throw Error('非法 JSON 值');i+=match[0].length;}
 value(0);ws();if(i!==text.length)throw Error('JSON 存在尾随内容');return JSON.parse(text);
}
function object(v){if(!v||typeof v!=='object'||Array.isArray(v))throw Error('需要对象');return v}
function shape(v,required,optional=[]){object(v);for(const k of required)if(!Object.hasOwn(v,k))throw Error('缺少字段：'+k);for(const k of Object.keys(v))if(!required.includes(k)&&!optional.includes(k))throw Error('未知字段：'+k)}
function string(v,max){if(typeof v!=='string'||v.length>max||/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(v))throw Error('字段字符串不合格');return v}
function parse(text){const v=parseStrict(text);
 shape(v,['format','demo','origin','signature','authorization_verified','release_qualified','observation','reference_sha256','inspection','history']);
 if(v.format!=='chronicle-observation/1'||v.demo!==false||v.signature!==null||v.authorization_verified!==false||v.release_qualified!==false)throw Error('只接受未认证的 observation/1 记录包；包内声明不能授予信任');
 string(v.origin,128);if(typeof v.reference_sha256!=='string'||!/^[a-f0-9]{64}$/.test(v.reference_sha256))throw Error('摘要格式不合格');
 const o=object(v.observation);shape(o,['repository','device','task_id','command','exit_code','output'],['id','output_next_offset','output_offset','output_total_bytes','output_truncated','status','term_signal','termination_unknown','timed_out']);
 if(o.repository!=='star8592/engineering-chronicle')throw Error('首版只接受当前项目');string(o.device,128);string(o.task_id,128);string(o.command,2048);string(o.output,500000);
 if(!Number.isInteger(o.exit_code)||o.exit_code<0||o.exit_code>255)throw Error('退出码不合格');
 if(o.output_truncated===true||o.timed_out===true||o.termination_unknown===true)throw Error('拒绝截断、超时或结束状态未知的观察');
 if(!Array.isArray(v.history)||v.history.length===0||v.history.length>128)throw Error('历史数量不合格');
 for(const e of v.history){shape(e,['time','title','type','commit','text','log','source','url']);for(const k of ['time','title','type','text','source'])string(e[k],2048);string(e.log,500000);if(typeof e.commit!=='string'||!/^[a-f0-9]{40}$/.test(e.commit))throw Error('提交格式不合格');if(typeof e.url!=='string'||!/^https:\/\/github\.com\/star8592\/engineering-chronicle\/(?:commit\/[a-f0-9]{40}|pull\/[1-9]\d*)$/.test(e.url))throw Error('只允许当前仓库的依据链接');}
 // Drop incoming inspection results. They are sender claims, never local verdicts.
 return {observation:o,history:v.history,reference_sha256:v.reference_sha256,origin:v.origin};
}
const api={parse,parseStrict,MAX_BYTES};if(typeof module==='object'&&module.exports)module.exports=api;else root.ChronicleBundle=api;
})(typeof globalThis==='object'?globalThis:this);
