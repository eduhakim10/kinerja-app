/* *
 *
 *  (c) 2010-2024 Torstein Honsi
 *
 *  License: www.highcharts.com/license
 *
 *  !!!!!!! SOURCE GETS TRANSPILED BY TYPESCRIPT. EDIT TS FILE ONLY. !!!!!!!
 *
 * */
'use strict';
import CU from '../../Series/CenteredUtilities.js';
import PaneComposition from './PaneComposition.js';
import PaneDefaults from './PaneDefaults.js';
import U from '../../Core/Utilities.js';
var extend = U.extend, merge = U.merge, splat = U.splat;
/* *
 *
 *  Class
 *
 * */
/**
 * The Pane object allows options that are common to a set of X and Y axes.
 *
 * In the future, this can be extended to basic Highcharts and Highcharts Stock.
 *
 * @private
 * @class
 * @name Highcharts.Pane
 * @param {Highcharts.PaneOptions} options
 * @param {Highcharts.Chart} chart
 */
var Pane = /** @class */ (function () {
    /* *
     *
     *  Constructor
     *
     * */
    function Pane(options, chart) {
        this.coll = 'pane'; // Member of chart.pane
        this.init(options, chart);
    }
    /* *
     *
     *  Functions
     *
     * */
    /**
     * Initialize the Pane object
     *
     * @private
     * @function Highcharts.Pane#init
     *
     * @param {Highcharts.PaneOptions} options
     *
     * @param {Highcharts.Chart} chart
     */
    Pane.prototype.init = function (options, chart) {
        this.chart = chart;
        this.background = [];
        chart.pane.push(this);
        this.setOptions(options);
    };
    /**
     * @private
     * @function Highcharts.Pane#setOptions
     *
     * @param {Highcharts.PaneOptions} options
     */
    Pane.prototype.setOptions = function (options) {
        // Set options. Angular charts have a default background (#3318)
        this.options = options = merge(PaneDefaults.pane, this.chart.angular ? { background: {} } : void 0, options);
    };
    /**
     * Render the pane with its backgrounds.
     *
     * @private
     * @function Highcharts.Pane#render
     */
    Pane.prototype.render = function () {
        var options = this.options, renderer = this.chart.renderer;
        if (!this.group) {
            this.group = renderer.g('pane-group')
                .attr({ zIndex: options.zIndex || 0 })
                .add();
        }
        this.updateCenter();
        var backgroundOption = this.options.background;
        // Render the backgrounds
        if (backgroundOption) {
            backgroundOption = splat(backgroundOption);
            var len = Math.max(backgroundOption.length, this.background.length || 0);
            for (var i = 0; i < len; i++) {
                // #6641 - if axis exists, chart is circular and apply
                // background
                if (backgroundOption[i] && this.axis) {
                    this.renderBackground(merge(PaneDefaults.background, backgroundOption[i]), i);
                }
                else if (this.background[i]) {
                    this.background[i] = this.background[i].destroy();
                    this.background.splice(i, 1);
                }
            }
        }
    };
    /**
     * Render an individual pane background.
     *
     * @private
     * @function Highcharts.Pane#renderBackground
     *
     * @param {Highcharts.PaneBackgroundOptions} backgroundOptions
     *        Background options
     *
     * @param {number} i
     *        The index of the background in this.backgrounds
     */
    Pane.prototype.renderBackground = function (backgroundOptions, i) {
        var attribs = {
            'class': 'highcharts-pane ' + (backgroundOptions.className || '')
        };
        var method = 'animate';
        if (!this.chart.styledMode) {
            extend(attribs, {
                'fill': backgroundOptions.backgroundColor,
                'stroke': backgroundOptions.borderColor,
                'stroke-width': backgroundOptions.borderWidth
            });
        }
        if (!this.background[i]) {
            this.background[i] = this.chart.renderer
                .path()
                .add(this.group);
            method = 'attr';
        }
        this.background[i][method]({
            'd': this.axis.getPlotBandPath(backgroundOptions.from, backgroundOptions.to, backgroundOptions)
        }).attr(attribs);
    };
    /**
     * Gets the center for the pane and its axis.
     *
     * @private
     * @function Highcharts.Pane#updateCenter
     * @param {Highcharts.Axis} [axis]
     */
    Pane.prototype.updateCenter = function (axis) {
        this.center = (axis ||
            this.axis ||
            {}).center = CU.getCenter.call(this);
    };
    /**
     * Destroy the pane item
     *
     * @ignore
     * @private
     * @function Highcharts.Pane#destroy
     * /
    destroy: function () {
        erase(this.chart.pane, this);
        this.background.forEach(function (background) {
            background.destroy();
        });
        this.background.length = 0;
        this.group = this.group.destroy();
    },
    */
    /**
     * Update the pane item with new options
     *
     * @private
     * @function Highcharts.Pane#update
     * @param {Highcharts.PaneOptions} options
     *        New pane options
     * @param {boolean} [redraw]
     */
    Pane.prototype.update = function (options, redraw) {
        merge(true, this.options, options);
        this.setOptions(this.options);
        this.render();
        this.chart.axes.forEach(function (axis) {
            if (axis.pane === this) {
                axis.pane = null;
                axis.update({}, redraw);
            }
        }, this);
    };
    /* *
     *
     *  Static Properties
     *
     * */
    Pane.compose = PaneComposition.compose;
    return Pane;
}());
/* *
 *
 *  Default Export
 *
 * */
export default Pane;
/* *
 *
 *  API Declarations
 *
 * */
/**
 * @typedef {"arc"|"circle"|"solid"} Highcharts.PaneBackgroundShapeValue
 */
''; // Keeps doclets above in JS file
