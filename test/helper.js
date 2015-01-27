
/**
 * Reset Mocha diff colors
 */

var colors = require('mocha/lib/reporters/base').colors;
colors['diff added'] = 32;
colors['diff removed'] = 31;
