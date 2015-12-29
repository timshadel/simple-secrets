var crypto = require('crypto');
var stats = require('simple-statistics');
var primitives = require('../lib/primitives');

function constantCompare(a, b) {
  assertBuffer(a, b);

  // things must be the same length to compare them.
  if (a.length != b.length) return false;

  var same = 0;
  for (var i = 0; i < a.length; i++) {
    same |= a[i] ^ b[i];
  }
  return same === 0;
}

function classicCompare(a, b) {
  if (a.length != b.length) return false;

  for (var i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

function bench(fns, datas) {
  var results = [];
  for (var f = 0; f < fns.length; f++) {
    results.push([]);
  }
  for (var i = 0; i < 1000; i++) {
    for (var j = 0; j < fns.length; j++) {
      var data = i % datas[j].length;
      var a = datas[j][data].a;
      var b = datas[j][data].b;
      var fn = fns[j];
      var time = process.hrtime();
      fn(a, b);
      results[j].push(process.hrtime(time));
    }
  }
  for (var r = 0; r < results.length; r++) {
    var sample = results[r];
    for (var s = 0; s < sample.length; s++) {
      sample[s] = sample[s][0] * 1e9 + sample[s][1];
    }
  }
  return results;
}

function invert(a) {
  var b = new Buffer(a.length);
  for (var i = 0; i < a.length; i++) {
    b[i] = a[i] ^ 0xff;
  }
  return b;
}

function filterOutliers(array) {
  var q1 = stats.quantile(array, 0.25);
  var q3 = stats.quantile(array, 0.75);
  var top = q3 + (q3-q1)*1.7;
  if (top - q3 < 15) top = q3 + 15;
  return array.filter(function(e) { return e < top; });
}


var datas = [ [], [] ];
var fns = [primitives.compare, primitives.compare];

for (var i = 0; i < 50; i++) {
  var a = crypto.randomBytes(250);
  datas[0].push({ a: a, b: invert(a) });
  datas[1].push({ a: new Buffer(a), b: new Buffer(a) });
}

var results = bench(fns, datas);
var t = stats.t_test_two_sample(results[0], results[1]);
t = Math.abs(t);

stemPlot('AB', filterOutliers(results[0]));
stemPlot('AA', filterOutliers(results[1]));

console.log('t', t, (t > 3.291) ? '>' : '<', '3.291');
if (t > 3.291) {
  console.log('Crypto cracked. Timing attack found.');
  console.log('Mean', stats.mean(results[0]), stats.mean(results[1]));
} else {
  console.log('Crypto safe. Timing indistinguishable.');
}


function stemPlot(title, sample) {
  var sprintfStr = require('sprintf-js').sprintf;
  var sprintf = function() { console.log(sprintfStr.apply(sprintf, arguments)); }
  var min = stem(stats.min(sample));
  var max = stem(stats.max(sample));
  var q1 = stats.quantile(sample, 0.25);
  var q3 = stats.quantile(sample, 0.75);
  var m = stats.mean(sample);
  var top = q3 + (q3-q1)*1.5;
  var sq1 = stem(q1);
  var sq3 = stem(q3);
  var sm = stem(m);
  var stop = stem(top);
  sample.sort(function(a,b) { return a - b; });
  var item = 0;
  console.log();
  console.log(title);
  console.log('Mean:', stats.mean(sample), 'StdDev:', stats.standard_deviation(sample));
  console.log('-------------------');
  for (var s = min; s <= max; s++) {
    var value = sample[item];
    var upper = (s+1) * 10;
    var leaves = '';
    while (value < upper) {
      leaves = leaves + leaf(value);
      value = sample[++item];
    }
    var label = '';
    if (s === sq1) label = 'Q1';
    if (s === sq3) label = 'Q3';
    if (s === sm) label = 'Mean';
    if (s === stop) label = 'Top';
    sprintf('%4s %2d|%s', label, s, leaves);
    // if (s === stop) break;
  }
}

function stem(value) {
  return Math.floor(value / 10);
}

function leaf(value) {
  return Math.floor(value - 10*stem(value));
}
