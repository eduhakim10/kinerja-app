!/**
 * Highstock JS v12.1.2 (2025-01-09)
 * @module highcharts/indicators/vwap
 * @requires highcharts
 * @requires highcharts/modules/stock
 *
 * Indicator series type for Highcharts Stock
 *
 * (c) 2010-2024 Paweł Dalek
 *
 * License: www.highcharts.com/license
 */function(e,t){"object"==typeof exports&&"object"==typeof module?module.exports=t(require("highcharts"),require("highcharts").SeriesRegistry):"function"==typeof define&&define.amd?define("highcharts/indicators/vwap",[["highcharts/highcharts"],["highcharts/highcharts","SeriesRegistry"]],t):"object"==typeof exports?exports["highcharts/indicators/vwap"]=t(require("highcharts"),require("highcharts").SeriesRegistry):e.Highcharts=t(e.Highcharts,e.Highcharts.SeriesRegistry)}(this,function(e,t){return function(){"use strict";var r,o={512:function(e){e.exports=t},944:function(t){t.exports=e}},n={};function i(e){var t=n[e];if(void 0!==t)return t.exports;var r=n[e]={exports:{}};return o[e](r,r.exports,i),r.exports}i.n=function(e){var t=e&&e.__esModule?function(){return e.default}:function(){return e};return i.d(t,{a:t}),t},i.d=function(e,t){for(var r in t)i.o(t,r)&&!i.o(e,r)&&Object.defineProperty(e,r,{enumerable:!0,get:t[r]})},i.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)};var u={};i.d(u,{default:function(){return v}});var s=i(944),a=i.n(s),c=i(512),h=i.n(c),p=(r=function(e,t){return(r=Object.setPrototypeOf||({__proto__:[]})instanceof Array&&function(e,t){e.__proto__=t}||function(e,t){for(var r in t)t.hasOwnProperty(r)&&(e[r]=t[r])})(e,t)},function(e,t){function o(){this.constructor=e}r(e,t),e.prototype=null===t?Object.create(t):(o.prototype=t.prototype,new o)}),f=h().seriesTypes.sma,l=a().error,y=a().isArray,g=a().merge,d=function(e){function t(){return null!==e&&e.apply(this,arguments)||this}return p(t,e),t.prototype.getValues=function(e,t){var r,o=e.chart,n=e.xData,i=e.yData,u=t.period,s=!0;if(!(r=o.get(t.volumeSeriesID))){l("Series "+t.volumeSeriesID+" not found! Check `volumeSeriesID`.",!0,o);return}return y(i[0])||(s=!1),this.calculateVWAPValues(s,n,i,r,u)},t.prototype.calculateVWAPValues=function(e,t,r,o,n){var i,u,s,a,c,h,p=o.getColumn("y"),f=p.length,l=t.length,y=[],g=[],d=[],v=[],m=[];for(c=0,i=l<=f?l:f,h=0;c<i;c++)u=(e?(r[c][1]+r[c][2]+r[c][3])/3:r[c])*p[c],s=h?y[c-1]+u:u,a=h?g[c-1]+p[c]:p[c],y.push(s),g.push(a),m.push([t[c],s/a]),d.push(m[c][0]),v.push(m[c][1]),++h===n&&(h=0);return{values:m,xData:d,yData:v}},t.defaultOptions=g(f.defaultOptions,{params:{index:void 0,period:30,volumeSeriesID:"volume"}}),t}(f);h().registerSeriesType("vwap",d);var v=a();return u.default}()});