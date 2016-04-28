/* ***** BEGIN LICENSE BLOCK *****
 *
 * _Array.from
 *
 * https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/from
 *
 * Any copyright is dedicated to the Public Domain.
 * http://creativecommons.org/publicdomain/zero/1.0/
 *
 * _cloneInto
 *
 * https://bugzilla.mozilla.org/show_bug.cgi?id=781521
 * https://bugzilla.mozilla.org/show_bug.cgi?id=1019643
 *
 * Version: MPL 2.0
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is Firefox.
 *
 * The Initial Developer of the Original Code is
 * The Mozilla Foundation.
 * Portions created by the Initial Developer are Copyright (C) 2012
 * the Initial Developer. All Rights Reserved.
 *
 * ***** END LICENSE BLOCK ***** */

var EXPORTED_SYMBOLS = ["_Array", "_cloneInto"];


var _Array = {};

// Production steps of ECMA-262, Edition 6, 22.1.2.1
// Reference:
// https://people.mozilla.org/~jorendorff/es6-draft.html#sec-array.from
_Array.from = (function () {
  var toStr = Object.prototype.toString;
  var isCallable = function (fn) {
    return typeof fn === "function" || toStr.call(fn) === "[object Function]";
  };
  var toInteger = function (value) {
    var number = Number(value);
    if (isNaN(number)) { return 0; }
    if (number === 0 || !isFinite(number)) { return number; }
    return (number > 0 ? 1 : -1) * Math.floor(Math.abs(number));
  };
  var maxSafeInteger = Math.pow(2, 53) - 1;
  var toLength = function (value) {
    var len = toInteger(value);
    return Math.min(Math.max(len, 0), maxSafeInteger);
  };

  // The length property of the from method is 1.
  return function from(arrayLike/*, mapFn, thisArg */) {
    // 1. Let C be the this value.
    var C = this;

    // 2. Let items be ToObject(arrayLike).
    var items = Object(arrayLike);

    // 3. ReturnIfAbrupt(items).
    if (arrayLike == null) {
      throw new TypeError(
          "Array.from requires an array-like object - not null or undefined");
    }

    // 4. If mapfn is undefined, then let mapping be false.
    var mapFn = arguments.length > 1 ? arguments[1] : void undefined;
    var T;
    if (typeof mapFn !== "undefined") {
      // 5. else      
      // 5. a If IsCallable(mapfn) is false, throw a TypeError exception.
      if (!isCallable(mapFn)) {
        throw new TypeError(
            "Array.from: when provided"
            + ", the second argument must be a function");
      }

      // 5. b. If thisArg was supplied, let T be thisArg;
      // else let T be undefined.
      if (arguments.length > 2) {
        T = arguments[2];
      }
    }

    // 10. Let lenValue be Get(items, "length").
    // 11. Let len be ToLength(lenValue).
    var len = toLength(items.length);

    // 13. If IsConstructor(C) is true, then
    // 13. a. Let A be the result of calling the [[Construct]]
    //     internal method of C with an argument list containing
    //     the single item len.
    // 14. a. Else, Let A be ArrayCreate(len).
    var A = isCallable(C) ? Object(new C(len)) : new Array(len);

    // 16. Let k be 0.
    var k = 0;
    // 17. Repeat, while k < len… (also steps a - h)
    var kValue;
    while (k < len) {
      kValue = items[k];
      if (mapFn) {
        A[k] = typeof T === "undefined"
            ? mapFn(kValue, k) : mapFn.call(T, kValue, k);
      } else {
        A[k] = kValue;
      }
      k += 1;
    }
    // 18. Let putStatus be Put(A, "length", len, true).
    A.length = len;
    // 20. Return A.
    return A;
  };
}());

function _cloneInto(aValue, aRewritableProps) {
  _cloneInto_(aValue, aRewritableProps);
  return aValue;
}

function _cloneInto_(aValue, aRewritableProps) {
  var exposedProps = "__exposedProps__";

  // Filter for Objects and Arrays.
  if (!aValue || ("object" !== typeof aValue)) {
    return;
  }

  // Recursively expose our children.
  Object.keys(aValue).forEach(function (key) {
    _cloneInto_(aValue[key], aRewritableProps);
  });

  // If we're not an Array, generate an __exposedProps__ object for ourselves.
  if (aValue instanceof Array) {
    return;
  }

  var exposed = {};
  Object.keys(aValue).forEach(function (key) {
    exposed[key] = (
        Array.isArray(aRewritableProps)
        && (aRewritableProps.indexOf(key) != -1))
        ? "rw" : "r";
  });

  aValue[exposedProps] = exposed;
}
