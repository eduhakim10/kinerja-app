!/**
 * Highcharts JS v12.1.2 (2025-01-09)
 * @module highcharts/modules/venn
 * @requires highcharts
 *
 * (c) 2017-2024 Highsoft AS
 * Authors: Jon Arild Nygard
 *
 * License: www.highcharts.com/license
 */function(t,e){"object"==typeof exports&&"object"==typeof module?module.exports=e(require("highcharts"),require("highcharts").Color,require("highcharts").SeriesRegistry):"function"==typeof define&&define.amd?define("highcharts/modules/venn",[["highcharts/highcharts"],["highcharts/highcharts","Color"],["highcharts/highcharts","SeriesRegistry"]],e):"object"==typeof exports?exports["highcharts/modules/venn"]=e(require("highcharts"),require("highcharts").Color,require("highcharts").SeriesRegistry):t.Highcharts=e(t.Highcharts,t.Highcharts.Color,t.Highcharts.SeriesRegistry)}(this,function(t,e,r){return function(){"use strict";var n,i,o,a,s,c={620:function(t){t.exports=e},512:function(t){t.exports=r},944:function(e){e.exports=t}},u={};function l(t){var e=u[t];if(void 0!==e)return e.exports;var r=u[t]={exports:{}};return c[t](r,r.exports,l),r.exports}l.n=function(t){var e=t&&t.__esModule?function(){return t.default}:function(){return t};return l.d(e,{a:e}),e},l.d=function(t,e){for(var r in e)l.o(e,r)&&!l.o(t,r)&&Object.defineProperty(t,r,{enumerable:!0,get:e[r]})},l.o=function(t,e){return Object.prototype.hasOwnProperty.call(t,e)};var f={};l.d(f,{default:function(){return td}});var p=l(944),h=l.n(p),g=l(620),d=l.n(g);(n=a||(a={})).getCenterOfPoints=function(t){var e=t.reduce(function(t,e){return t.x+=e.x,t.y+=e.y,t},{x:0,y:0});return{x:e.x/t.length,y:e.y/t.length}},n.getDistanceBetweenPoints=function(t,e){return Math.sqrt(Math.pow(e.x-t.x,2)+Math.pow(e.y-t.y,2))},n.getAngleBetweenPoints=function(t,e){return Math.atan2(e.x-t.x,e.y-t.y)},n.pointInPolygon=function(t,e){var r,n,i=t.x,o=t.y,a=e.length,s=!1;for(r=0,n=a-1;r<a;n=r++){var c=e[r],u=c[0],l=c[1],f=e[n],p=f[0],h=f[1];l>o!=h>o&&i<(p-u)*(o-l)/(h-l)+u&&(s=!s)}return s};var y=a,v=y.getAngleBetweenPoints,x=y.getCenterOfPoints,m=y.getDistanceBetweenPoints;!function(t){function e(t,e){var r=Math.pow(10,e);return Math.round(t*r)/r}function r(t){if(t<=0)throw Error("radius of circle must be a positive number.");return Math.PI*t*t}function n(t,e){return t*t*Math.acos(1-e/t)-(t-e)*Math.sqrt(e*(2*t-e))}function i(t,r){var n=m(t,r),i=t.r,o=r.r,a=[];if(n<i+o&&n>Math.abs(i-o)){var s=i*i,c=(s-o*o+n*n)/(2*n),u=Math.sqrt(s-c*c),l=t.x,f=r.x,p=t.y,h=r.y,g=l+c*(f-l)/n,d=p+c*(h-p)/n,y=-(u/n*(h-p)),v=-(u/n*(f-l));a=[{x:e(g+y,14),y:e(d-v,14)},{x:e(g-y,14),y:e(d+v,14)}]}return a}function o(t){return t.reduce(function(t,e,r,n){var o=n.slice(r+1).reduce(function(t,n,o){var a=[r,o+r+1];return t.concat(i(e,n).map(function(t){return t.indexes=a,t}))},[]);return t.concat(o)},[])}function a(t,e){return m(t,e)<=e.r+1e-10}function s(t,e){return!e.some(function(e){return!a(t,e)})}function c(t){return o(t).filter(function(e){return s(e,t)})}t.round=e,t.getAreaOfCircle=r,t.getCircularSegmentArea=n,t.getOverlapBetweenCircles=function(t,i,o){var a=0;if(o<t+i){if(o<=Math.abs(i-t))a=r(t<i?t:i);else{var s=(t*t-i*i+o*o)/(2*o);a=n(t,t-s)+n(i,i-(o-s))}a=e(a,14)}return a},t.getCircleCircleIntersection=i,t.getCirclesIntersectionPoints=o,t.isCircle1CompletelyOverlappingCircle2=function(t,e){return m(t,e)+e.r<t.r+1e-10},t.isPointInsideCircle=a,t.isPointInsideAllCircles=s,t.isPointOutsideAllCircles=function(t,e){return!e.some(function(e){return a(t,e)})},t.getCirclesIntersectionPolygon=c,t.getAreaOfIntersectionBetweenCircles=function(t){var e,r=c(t);if(r.length>1){var n=x(r),i=(r=r.map(function(t){return t.angle=v(n,t),t}).sort(function(t,e){return e.angle-t.angle}))[r.length-1],o=r.reduce(function(e,r){var n=e.startPoint,i=x([n,r]),o=r.indexes.filter(function(t){return n.indexes.indexOf(t)>-1}).reduce(function(e,o){var a=t[o],s=v(a,r),c=v(a,n),u=c-s+(c<s?2*Math.PI:0),l=c-u/2,f=m(i,{x:a.x+a.r*Math.sin(l),y:a.y+a.r*Math.cos(l)}),p=a.r;return f>2*p&&(f=2*p),(!e||e.width>f)&&(e={r:p,largeArc:f>p?1:0,width:f,x:r.x,y:r.y}),e},null);if(o){var a=o.r;e.arcs.push(["A",a,a,0,o.largeArc,1,o.x,o.y]),e.startPoint=r}return e},{startPoint:i,arcs:[]}).arcs;0===o.length||1===o.length||(o.unshift(["M",i.x,i.y]),e={center:n,d:o})}return e}}(s||(s={}));var b=s,O=function(){return(O=Object.assign||function(t){for(var e,r=1,n=arguments.length;r<n;r++)for(var i in e=arguments[r])Object.prototype.hasOwnProperty.call(e,i)&&(t[i]=e[i]);return t}).apply(this,arguments)},C={draw:function(t,e){var r=e.animatableAttribs,n=e.onComplete,i=e.css,o=e.renderer,a=t.series&&t.series.chart.hasRendered?void 0:t.series&&t.series.options.animation,s=t.graphic;if(e.attribs=O(O({},e.attribs),{class:t.getClassName()})||{},t.shouldDraw())s||(s="text"===e.shapeType?o.text():"image"===e.shapeType?o.image(e.imageUrl||"").attr(e.shapeArgs||{}):o[e.shapeType](e.shapeArgs||{}),t.graphic=s,s.add(e.group)),i&&s.css(i),s.attr(e.attribs).animate(r,!e.isNew&&a,n);else if(s){var c=function(){t.graphic=s=s&&s.destroy(),"function"==typeof n&&n()};Object.keys(r).length?s.animate(r,void 0,function(){return c()}):c()}}},A=l(512),P=l.n(A),w=(i=function(t,e){return(i=Object.setPrototypeOf||({__proto__:[]})instanceof Array&&function(t,e){t.__proto__=e}||function(t,e){for(var r in e)e.hasOwnProperty(r)&&(t[r]=e[r])})(t,e)},function(t,e){function r(){this.constructor=t}i(t,e),t.prototype=null===e?Object.create(e):(r.prototype=e.prototype,new r)}),M=P().seriesTypes.scatter.prototype.pointClass,j=h().isNumber,_=function(t){function e(){return null!==t&&t.apply(this,arguments)||this}return w(e,t),e.prototype.isValid=function(){return j(this.value)},e.prototype.shouldDraw=function(){return!!this.shapeArgs},e}(M),I={borderColor:"#cccccc",borderDashStyle:"solid",borderWidth:1,brighten:0,clip:!1,colorByPoint:!0,dataLabels:{enabled:!0,verticalAlign:"middle",formatter:function(){return this.point.name}},inactiveOtherPoints:!0,marker:!1,opacity:.75,showInLegend:!1,legendType:"point",states:{hover:{opacity:1,borderColor:"#333333"},select:{color:"#cccccc",borderColor:"#000000",animation:!1},inactive:{opacity:.075}},tooltip:{pointFormat:"{point.name}: {point.value}"},legendSymbol:"rectangle"},S=function(){return(S=Object.assign||function(t){for(var e,r=1,n=arguments.length;r<n;r++)for(var i in e=arguments[r])Object.prototype.hasOwnProperty.call(e,i)&&(t[i]=e[i]);return t}).apply(this,arguments)},T=b.getAreaOfCircle,E=b.getCircleCircleIntersection,L=b.getOverlapBetweenCircles,B=b.isPointInsideAllCircles,V=b.isPointInsideCircle,N=b.isPointOutsideAllCircles,q=y.getDistanceBetweenPoints,D=h().extend,X=h().isArray,k=h().isNumber,U=h().isObject,F=h().isString;function H(t){var e={};return t.filter(function(t){return 2===t.sets.length}).forEach(function(t){t.sets.forEach(function(r,n,i){var o;U(e[r])||(e[r]={totalOverlap:0,overlapping:{}}),e[r]={totalOverlap:(e[r].totalOverlap||0)+t.value,overlapping:S(S({},e[r].overlapping||{}),((o={})[i[1-n]]=t.value,o))}})}),t.filter(G).forEach(function(t){var r=e[t.sets[0]];D(t,r)}),t}function R(t,e,r,n,i){var o,a,s=t(e),c=t(r),u=i||100,l=n||1e-10,f=r-e,p=1;if(e>=r)throw Error("a must be smaller than b.");if(s*c>0)throw Error("f(a) and f(b) must have opposite signs.");if(0===s)o=e;else if(0===c)o=r;else for(;p++<=u&&0!==a&&f>l;)f=(r-e)/2,s*(a=t(o=e+f))>0?e=o:r=o;return o}function W(t){for(var e=t.slice(0,-1),r=e.length,n=[],i=function(t,e){return t.sum+=e[t.i],t},o=0;o<r;o++)n[o]=e.reduce(i,{sum:0,i:o}).sum/r;return n}function Y(t,e,r){var n=t+e;return r<=0?n:T(t<e?t:e)<=r?0:R(function(n){return r-L(t,e,n)},0,n)}function G(t){return X(t.sets)&&1===t.sets.length}function z(t){var e={};return U(t)&&k(t.value)&&t.value>-1&&X(t.sets)&&t.sets.length>0&&!t.sets.some(function(t){var r=!1;return!e[t]&&F(t)?e[t]=!0:r=!0,r})}function J(t,e){return e.reduce(function(e,r){var n=0;if(r.sets.length>1){var i=r.value-function(t){var e=0;if(2===t.length){var r=t[0],n=t[1];e=L(r.r,n.r,q(r,n))}return e}(r.sets.map(function(e){return t[e]}));n=Math.round(i*i*1e11)/1e11}return e+n},0)}function K(t,e){return void 0!==e.totalOverlap&&void 0!==t.totalOverlap?e.totalOverlap-t.totalOverlap:NaN}var Q={geometry:y,geometryCircles:b,addOverlapToSets:H,getCentroid:W,getDistanceBetweenCirclesByOverlap:Y,getLabelWidth:function(t,e,r){var n=e.reduce(function(t,e){return Math.min(e.r,t)},1/0),i=r.filter(function(e){return!V(t,e)}),o=function(r,n){return R(function(o){var a={x:t.x+n*o,y:t.y};return-(r-o)+(B(a,e)&&N(a,i)?0:Number.MAX_VALUE)},0,r)};return 2*Math.min(o(n,-1),o(n,1))},getMarginFromCircles:function(t,e,r){var n=e.reduce(function(e,r){var n=r.r-q(t,r);return n<=e?n:e},Number.MAX_VALUE);return r.reduce(function(e,r){var n=q(t,r)-r.r;return n<=e?n:e},n)},isSet:G,layoutGreedyVenn:function(t){var e=[],r={};t.filter(function(t){return 1===t.sets.length}).forEach(function(t){r[t.sets[0]]=t.circle={x:Number.MAX_VALUE,y:Number.MAX_VALUE,r:Math.sqrt(t.value/Math.PI)}});var n=function(t,r){var n=t.circle;n&&(n.x=r.x,n.y=r.y),e.push(t)};H(t);var i=t.filter(G).sort(K);n(i.shift(),{x:0,y:0});for(var o=t.filter(function(t){return 2===t.sets.length}),a=0;a<i.length;a++)!function(t){var i=t.circle;if(i){var a=i.r,s=t.overlapping;n(t,e.reduce(function(t,n,c){var u=n.circle;if(!u||!s)return t;for(var l=s[n.sets[0]],f=Y(a,u.r,l),p=[{x:u.x+f,y:u.y},{x:u.x-f,y:u.y},{x:u.x,y:u.y+f},{x:u.x,y:u.y-f}],h=0,g=e.slice(c+1);h<g.length;h++){var d=g[h],y=d.circle,v=s[d.sets[0]];if(y){var x=Y(a,y.r,v);p=p.concat(E({x:u.x,y:u.y,r:f},{x:y.x,y:y.y,r:x}))}}for(var m=0,b=p;m<b.length;m++){var O=b[m];i.x=O.x,i.y=O.y;var C=J(r,o);C<t.loss&&(t.loss=C,t.coordinates=O)}return t},{loss:Number.MAX_VALUE,coordinates:void 0}).coordinates)}}(i[a]);return r},loss:J,nelderMead:function(t,e){for(var r=function(t,e){return t.fx-e.fx},n=function(t,e,r,n){return e.map(function(e,i){return t*e+r*n[i]})},i=function(e,r){return r.fx=t(r),e[e.length-1]=r,e},o=function(e){var r=e[0];return e.map(function(e){var i=n(.5,r,.5,e);return i.fx=t(i),i})},a=function(e,r,i,o){var a=n(i,e,o,r);return a.fx=t(a),a},s=function(e){var r=e.length,n=Array(r+1);n[0]=e,n[0].fx=t(e);for(var i=0;i<r;++i){var o=e.slice();o[i]=o[i]?1.05*o[i]:.001,o.fx=t(o),n[i+1]=o}return n}(e),c=0;c<100;c++){s.sort(r);var u=s[s.length-1],l=W(s),f=a(l,u,2,-1);if(f.fx<s[0].fx){var p=a(l,u,3,-2);s=i(s,p.fx<f.fx?p:f)}else if(f.fx>=s[s.length-2].fx){var h=void 0;s=f.fx>u.fx?(h=a(l,u,.5,.5)).fx<u.fx?i(s,h):o(s):(h=a(l,u,1.5,-.5)).fx<f.fx?i(s,h):o(s)}else s=i(s,f)}return s[0]},processVennData:function(t,e){var r=X(t)?t:[],n=r.reduce(function(t,e){var r;return e.sets&&z(r=e)&&G(r)&&r.value>0&&-1===t.indexOf(e.sets[0])&&t.push(e.sets[0]),t},[]).sort(),i=r.reduce(function(t,r){return r.sets&&z(r)&&!r.sets.some(function(t){return -1===n.indexOf(t)})&&(t[r.sets.sort().join(e)]={sets:r.sets,value:r.value||0}),t},{});return n.reduce(function(t,r,n,i){return i.slice(n+1).forEach(function(n){t.push(r+e+n)}),t},[]).forEach(function(t){if(!i[t]){var r={sets:t.split(e),value:0};i[t]=r}}),Object.keys(i).map(function(t){return i[t]})},sortByTotalOverlap:K},Z=(o=function(t,e){return(o=Object.setPrototypeOf||({__proto__:[]})instanceof Array&&function(t,e){t.__proto__=e}||function(t,e){for(var r in e)Object.prototype.hasOwnProperty.call(e,r)&&(t[r]=e[r])})(t,e)},function(t,e){if("function"!=typeof e&&null!==e)throw TypeError("Class extends value "+String(e)+" is not a constructor or null");function r(){this.constructor=t}o(t,e),t.prototype=null===e?Object.create(e):(r.prototype=e.prototype,new r)}),$=h().animObject,tt=d().parse,te=b.getAreaOfIntersectionBetweenCircles,tr=b.getCirclesIntersectionPolygon,tn=b.isCircle1CompletelyOverlappingCircle2,ti=b.isPointInsideAllCircles,to=b.isPointOutsideAllCircles,ta=y.getCenterOfPoints,ts=P().seriesTypes.scatter,tc=h().addEvent,tu=h().extend,tl=h().isArray,tf=h().isNumber,tp=h().isObject,th=h().merge,tg=function(t){function e(){return null!==t&&t.apply(this,arguments)||this}return Z(e,t),e.getLabelPosition=function(t,e){var r=t.reduce(function(r,n){var i=n.r/2;return[{x:n.x,y:n.y},{x:n.x+i,y:n.y},{x:n.x-i,y:n.y},{x:n.x,y:n.y+i},{x:n.x,y:n.y-i}].reduce(function(r,n){var i=Q.getMarginFromCircles(n,t,e);return r.margin<i&&(r.point=n,r.margin=i),r},r)},{point:void 0,margin:-Number.MAX_VALUE}).point,n=Q.nelderMead(function(r){return-Q.getMarginFromCircles({x:r[0],y:r[1]},t,e)},[r.x,r.y]);return ti(r={x:n[0],y:n[1]},t)&&to(r,e)||(r=t.length>1?ta(tr(t)):{x:t[0].x,y:t[0].y}),r},e.getLabelValues=function(t,r){var n=t.sets,i=r.reduce(function(t,e){var r=n.indexOf(e.sets[0])>-1;return e.circle&&t[r?"internal":"external"].push(e.circle),t},{internal:[],external:[]});i.external=i.external.filter(function(t){return i.internal.some(function(e){return!tn(t,e)})});var o=e.getLabelPosition(i.internal,i.external),a=Q.getLabelWidth(o,i.internal,i.external);return{position:o,width:a}},e.layout=function(t){var r={},n={};if(t.length>0)for(var i=Q.layoutGreedyVenn(t),o=t.filter(Q.isSet),a=0;a<t.length;a++){var s=t[a],c=s.sets,u=c.join(),l=Q.isSet(s)?i[u]:te(c.map(function(t){return i[t]}));l&&(r[u]=l,n[u]=e.getLabelValues(s,o))}return{mapOfIdToShape:r,mapOfIdToLabelValues:n}},e.getScale=function(t,e,r){var n=r.bottom-r.top,i=r.right-r.left,o=(r.right+r.left)/2,a=(r.top+r.bottom)/2,s=Math.min(i>0?1/i*t:1,n>0?1/n*e:1);return{scale:s,centerX:t/2-o*s,centerY:e/2-a*s}},e.updateFieldBoundaries=function(t,e){var r=e.x-e.r,n=e.x+e.r,i=e.y+e.r,o=e.y-e.r;return(!tf(t.left)||t.left>r)&&(t.left=r),(!tf(t.right)||t.right<n)&&(t.right=n),(!tf(t.top)||t.top>o)&&(t.top=o),(!tf(t.bottom)||t.bottom<i)&&(t.bottom=i),t},e.prototype.animate=function(t){if(!t)for(var e=$(this.options.animation),r=function(t){var r=t.shapeArgs;if(t.graphic&&r){var n={},i={};r.d?n.opacity=.001:(n.r=0,i.r=r.r),t.graphic.attr(n).animate(i,e),r.d&&setTimeout(function(){t&&t.graphic&&t.graphic.animate({opacity:1})},e.duration)}},n=0,i=this.points;n<i.length;n++)r(i[n])},e.prototype.drawPoints=function(){for(var t=this.chart,e=this.group,r=this.points||[],n=t.renderer,i=0;i<r.length;i++){var o=r[i],a={zIndex:tl(o.sets)?o.sets.length:0},s=o.shapeArgs;t.styledMode||tu(a,this.pointAttribs(o,o.state)),C.draw(o,{isNew:!o.graphic,animatableAttribs:s,attribs:a,group:e,renderer:n,shapeType:s&&s.d?"path":"circle"})}},e.prototype.init=function(){ts.prototype.init.apply(this,arguments),delete this.opacity},e.prototype.pointAttribs=function(t,e){var r=this.options||{},n=t&&t.options||{},i=e&&r.states[e]||{},o=th(r,{color:t&&t.color},n,i);return{fill:tt(o.color).brighten(o.brightness).get(),opacity:o.opacity,stroke:o.borderColor,"stroke-width":o.borderWidth,dashstyle:o.borderDashStyle}},e.prototype.translate=function(){var t=this.chart;this.dataTable.modified=this.dataTable,this.generatePoints();for(var r=Q.processVennData(this.options.data,e.splitter),n=e.layout(r),i=n.mapOfIdToShape,o=n.mapOfIdToLabelValues,a=Object.keys(i).filter(function(t){var e=i[t];return e&&tf(e.r)}).reduce(function(t,r){return e.updateFieldBoundaries(t,i[r])},{top:0,bottom:0,left:0,right:0}),s=e.getScale(t.plotWidth,t.plotHeight,a),c=s.scale,u=s.centerX,l=s.centerY,f=0,p=this.points;f<p.length;f++){var h=p[f],g=tl(h.sets)?h.sets:[],d=g.join(),y=i[d],v=o[d]||{},x=h.options&&h.options.dataLabels,m=void 0,b=v.width,O=v.position;if(y){if(y.r)m={x:u+y.x*c,y:l+y.y*c,r:y.r*c};else if(y.d){var C=y.d;C.forEach(function(t){"M"===t[0]?(t[1]=u+t[1]*c,t[2]=l+t[2]*c):"A"===t[0]&&(t[1]=t[1]*c,t[2]=t[2]*c,t[6]=u+t[6]*c,t[7]=l+t[7]*c)}),m={d:C}}O?(O.x=u+O.x*c,O.y=l+O.y*c):O={},tf(b)&&(b=Math.round(b*c))}h.shapeArgs=m,O&&m&&(h.plotX=O.x,h.plotY=O.y),b&&m&&(h.dlOptions=th(!0,{style:{width:b}},tp(x,!0)?x:void 0)),h.name=h.options.name||g.join("∩")}},e.splitter="highcharts-split",e.defaultOptions=th(ts.defaultOptions,I),e}(ts);tu(tg.prototype,{axisTypes:[],directTouch:!0,isCartesian:!1,pointArrayMap:["value"],pointClass:_,utils:Q}),tc(tg,"afterSetOptions",function(t){var e=t.options.states||{};if(this.is("venn"))for(var r=0,n=Object.keys(e);r<n.length;r++)e[n[r]].halo=!1}),P().registerSeriesType("venn",tg);var td=h();return f.default}()});