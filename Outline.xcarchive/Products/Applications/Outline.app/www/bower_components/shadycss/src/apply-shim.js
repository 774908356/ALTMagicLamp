/**
@license
Copyright (c) 2017 The Polymer Project Authors. All rights reserved.
This code may only be used under the BSD style license found at http://polymer.github.io/LICENSE.txt
The complete set of authors may be found at http://polymer.github.io/AUTHORS.txt
The complete set of contributors may be found at http://polymer.github.io/CONTRIBUTORS.txt
Code distributed by Google as part of the polymer project is also
subject to an additional IP rights grant found at http://polymer.github.io/PATENTS.txt
*/
/*
 * The apply shim simulates the behavior of `@apply` proposed at
 * https://tabatkins.github.io/specs/css-apply-rule/.
 * The approach is to convert a property like this:
 *
 *    --foo: {color: red; background: blue;}
 *
 * to this:
 *
 *    --foo_-_color: red;
 *    --foo_-_background: blue;
 *
 * Then where `@apply --foo` is used, that is converted to:
 *
 *    color: var(--foo_-_color);
 *    background: var(--foo_-_background);
 *
 * This approach generally works but there are some issues and limitations.
 * Consider, for example, that somewhere *between* where `--foo` is set and used,
 * another element sets it to:
 *
 *    --foo: { border: 2px solid red; }
 *
 * We must now ensure that the color and background from the previous setting
 * do not apply. This is accomplished by changing the property set to this:
 *
 *    --foo_-_border: 2px solid red;
 *    --foo_-_color: initial;
 *    --foo_-_background: initial;
 *
 * This works but introduces one new issue.
 * Consider this setup at the point where the `@apply` is used:
 *
 *    background: orange;
 *    `@apply` --foo;
 *
 * In this case the background will be unset (initial) rather than the desired
 * `orange`. We address this by altering the property set to use a fallback
 * value like this:
 *
 *    color: var(--foo_-_color);
 *    background: var(--foo_-_background, orange);
 *    border: var(--foo_-_border);
 *
 * Note that the default is retained in the property set and the `background` is
 * the desired `orange`. This leads us to a limitation.
 *
 * Limitation 1:

 * Only properties in the rule where the `@apply`
 * is used are considered as default values.
 * If another rule matches the element and sets `background` with
 * less specificity than the rule in which `@apply` appears,
 * the `background` will not be set.
 *
 * Limitation 2:
 *
 * When using Polymer's `updateStyles` api, new properties may not be set for
 * `@apply` properties.

*/

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _styleUtil = require('./style-util.js');

var _commonRegex = require('./common-regex.js');

var _commonUtils = require('./common-utils.js');

var _cssParse = require('./css-parse.js');

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

// eslint-disable-line no-unused-vars

var APPLY_NAME_CLEAN = /;\s*/m;
var INITIAL_INHERIT = /^\s*(initial)|(inherit)\s*$/;
var IMPORTANT = /\s*!important/;

// separator used between mixin-name and mixin-property-name when producing properties
// NOTE: plain '-' may cause collisions in user styles
var MIXIN_VAR_SEP = '_-_';

/**
 * @typedef {!Object<string, string>}
 */
var PropertyEntry = void 0; // eslint-disable-line no-unused-vars

/**
 * @typedef {!Object<string, boolean>}
 */
var DependantsEntry = void 0; // eslint-disable-line no-unused-vars

/** @typedef {{
 *    properties: PropertyEntry,
 *    dependants: DependantsEntry
 * }}
 */
var MixinMapEntry = void 0; // eslint-disable-line no-unused-vars

// map of mixin to property names
// --foo: {border: 2px} -> {properties: {(--foo, ['border'])}, dependants: {'element-name': proto}}

var MixinMap = function () {
  function MixinMap() {
    _classCallCheck(this, MixinMap);

    /** @type {!Object<string, !MixinMapEntry>} */
    this._map = {};
  }
  /**
   * @param {string} name
   * @param {!PropertyEntry} props
   */


  _createClass(MixinMap, [{
    key: 'set',
    value: function set(name, props) {
      name = name.trim();
      this._map[name] = {
        properties: props,
        dependants: {}
      };
    }
    /**
     * @param {string} name
     * @return {MixinMapEntry}
     */

  }, {
    key: 'get',
    value: function get(name) {
      name = name.trim();
      return this._map[name] || null;
    }
  }]);

  return MixinMap;
}();

/**
 * Callback for when an element is marked invalid
 * @type {?function(string)}
 */


var invalidCallback = null;

/** @unrestricted */

var ApplyShim = function () {
  function ApplyShim() {
    _classCallCheck(this, ApplyShim);

    /** @type {?string} */
    this._currentElement = null;
    /** @type {HTMLMetaElement} */
    this._measureElement = null;
    this._map = new MixinMap();
  }
  /**
   * return true if `cssText` contains a mixin definition or consumption
   * @param {string} cssText
   * @return {boolean}
   */


  _createClass(ApplyShim, [{
    key: 'detectMixin',
    value: function detectMixin(cssText) {
      return (0, _commonUtils.detectMixin)(cssText);
    }

    /**
     * Gather styles into one style for easier processing
     * @param {!HTMLTemplateElement} template
     * @return {HTMLStyleElement}
     */

  }, {
    key: 'gatherStyles',
    value: function gatherStyles(template) {
      var styleText = (0, _styleUtil.gatherStyleText)(template.content);
      if (styleText) {
        var style = /** @type {!HTMLStyleElement} */document.createElement('style');
        style.textContent = styleText;
        template.content.insertBefore(style, template.content.firstChild);
        return style;
      }
      return null;
    }
    /**
     * @param {!HTMLTemplateElement} template
     * @param {string} elementName
     * @return {StyleNode}
     */

  }, {
    key: 'transformTemplate',
    value: function transformTemplate(template, elementName) {
      if (template._gatheredStyle === undefined) {
        template._gatheredStyle = this.gatherStyles(template);
      }
      /** @type {HTMLStyleElement} */
      var style = template._gatheredStyle;
      return style ? this.transformStyle(style, elementName) : null;
    }
    /**
     * @param {!HTMLStyleElement} style
     * @param {string} elementName
     * @return {StyleNode}
     */

  }, {
    key: 'transformStyle',
    value: function transformStyle(style) {
      var elementName = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : '';

      var ast = (0, _styleUtil.rulesForStyle)(style);
      this.transformRules(ast, elementName);
      style.textContent = (0, _styleUtil.toCssText)(ast);
      return ast;
    }
    /**
     * @param {!HTMLStyleElement} style
     * @return {StyleNode}
     */

  }, {
    key: 'transformCustomStyle',
    value: function transformCustomStyle(style) {
      var _this = this;

      var ast = (0, _styleUtil.rulesForStyle)(style);
      (0, _styleUtil.forEachRule)(ast, function (rule) {
        if (rule['selector'] === ':root') {
          rule['selector'] = 'html';
        }
        _this.transformRule(rule);
      });
      style.textContent = (0, _styleUtil.toCssText)(ast);
      return ast;
    }
    /**
     * @param {StyleNode} rules
     * @param {string} elementName
     */

  }, {
    key: 'transformRules',
    value: function transformRules(rules, elementName) {
      var _this2 = this;

      this._currentElement = elementName;
      (0, _styleUtil.forEachRule)(rules, function (r) {
        _this2.transformRule(r);
      });
      this._currentElement = null;
    }
    /**
     * @param {!StyleNode} rule
     */

  }, {
    key: 'transformRule',
    value: function transformRule(rule) {
      rule['cssText'] = this.transformCssText(rule['parsedCssText'], rule);
      // :root was only used for variable assignment in property shim,
      // but generates invalid selectors with real properties.
      // replace with `:host > *`, which serves the same effect
      if (rule['selector'] === ':root') {
        rule['selector'] = ':host > *';
      }
    }
    /**
     * @param {string} cssText
     * @param {!StyleNode} rule
     * @return {string}
     */

  }, {
    key: 'transformCssText',
    value: function transformCssText(cssText, rule) {
      var _this3 = this;

      // produce variables
      cssText = cssText.replace(_commonRegex.VAR_ASSIGN, function (matchText, propertyName, valueProperty, valueMixin) {
        return _this3._produceCssProperties(matchText, propertyName, valueProperty, valueMixin, rule);
      });
      // consume mixins
      return this._consumeCssProperties(cssText, rule);
    }
    /**
     * @param {string} property
     * @return {string}
     */

  }, {
    key: '_getInitialValueForProperty',
    value: function _getInitialValueForProperty(property) {
      if (!this._measureElement) {
        this._measureElement = /** @type {HTMLMetaElement} */document.createElement('meta');
        this._measureElement.setAttribute('apply-shim-measure', '');
        this._measureElement.style.all = 'initial';
        document.head.appendChild(this._measureElement);
      }
      return window.getComputedStyle(this._measureElement).getPropertyValue(property);
    }
    /**
     * Walk over all rules before this rule to find fallbacks for mixins
     *
     * @param {!StyleNode} startRule
     * @return {!Object}
     */

  }, {
    key: '_fallbacksFromPreviousRules',
    value: function _fallbacksFromPreviousRules(startRule) {
      var _this4 = this;

      // find the "top" rule
      var topRule = startRule;
      while (topRule['parent']) {
        topRule = topRule['parent'];
      }
      var fallbacks = {};
      var seenStartRule = false;
      (0, _styleUtil.forEachRule)(topRule, function (r) {
        // stop when we hit the input rule
        seenStartRule = seenStartRule || r === startRule;
        if (seenStartRule) {
          return;
        }
        // NOTE: Only matching selectors are "safe" for this fallback processing
        // It would be prohibitive to run `matchesSelector()` on each selector,
        // so we cheat and only check if the same selector string is used, which
        // guarantees things like specificity matching
        if (r['selector'] === startRule['selector']) {
          Object.assign(fallbacks, _this4._cssTextToMap(r['parsedCssText']));
        }
      });
      return fallbacks;
    }
    /**
     * replace mixin consumption with variable consumption
     * @param {string} text
     * @param {!StyleNode=} rule
     * @return {string}
     */

  }, {
    key: '_consumeCssProperties',
    value: function _consumeCssProperties(text, rule) {
      /** @type {Array} */
      var m = null;
      // loop over text until all mixins with defintions have been applied
      while (m = _commonRegex.MIXIN_MATCH.exec(text)) {
        var matchText = m[0];
        var mixinName = m[1];
        var idx = m.index;
        // collect properties before apply to be "defaults" if mixin might override them
        // match includes a "prefix", so find the start and end positions of @apply
        var applyPos = idx + matchText.indexOf('@apply');
        var afterApplyPos = idx + matchText.length;
        // find props defined before this @apply
        var textBeforeApply = text.slice(0, applyPos);
        var textAfterApply = text.slice(afterApplyPos);
        var defaults = rule ? this._fallbacksFromPreviousRules(rule) : {};
        Object.assign(defaults, this._cssTextToMap(textBeforeApply));
        var replacement = this._atApplyToCssProperties(mixinName, defaults);
        // use regex match position to replace mixin, keep linear processing time
        text = '' + textBeforeApply + replacement + textAfterApply;
        // move regex search to _after_ replacement
        _commonRegex.MIXIN_MATCH.lastIndex = idx + replacement.length;
      }
      return text;
    }
    /**
     * produce variable consumption at the site of mixin consumption
     * `@apply` --foo; -> for all props (${propname}: var(--foo_-_${propname}, ${fallback[propname]}}))
     * Example:
     *  border: var(--foo_-_border); padding: var(--foo_-_padding, 2px)
     *
     * @param {string} mixinName
     * @param {Object} fallbacks
     * @return {string}
     */

  }, {
    key: '_atApplyToCssProperties',
    value: function _atApplyToCssProperties(mixinName, fallbacks) {
      mixinName = mixinName.replace(APPLY_NAME_CLEAN, '');
      var vars = [];
      var mixinEntry = this._map.get(mixinName);
      // if we depend on a mixin before it is created
      // make a sentinel entry in the map to add this element as a dependency for when it is defined.
      if (!mixinEntry) {
        this._map.set(mixinName, {});
        mixinEntry = this._map.get(mixinName);
      }
      if (mixinEntry) {
        if (this._currentElement) {
          mixinEntry.dependants[this._currentElement] = true;
        }
        var p = void 0,
            parts = void 0,
            f = void 0;
        var properties = mixinEntry.properties;
        for (p in properties) {
          f = fallbacks && fallbacks[p];
          parts = [p, ': var(', mixinName, MIXIN_VAR_SEP, p];
          if (f) {
            parts.push(',', f.replace(IMPORTANT, ''));
          }
          parts.push(')');
          if (IMPORTANT.test(properties[p])) {
            parts.push(' !important');
          }
          vars.push(parts.join(''));
        }
      }
      return vars.join('; ');
    }

    /**
     * @param {string} property
     * @param {string} value
     * @return {string}
     */

  }, {
    key: '_replaceInitialOrInherit',
    value: function _replaceInitialOrInherit(property, value) {
      var match = INITIAL_INHERIT.exec(value);
      if (match) {
        if (match[1]) {
          // initial
          // replace `initial` with the concrete initial value for this property
          value = this._getInitialValueForProperty(property);
        } else {
          // inherit
          // with this purposfully illegal value, the variable will be invalid at
          // compute time (https://www.w3.org/TR/css-variables/#invalid-at-computed-value-time)
          // and for inheriting values, will behave similarly
          // we cannot support the same behavior for non inheriting values like 'border'
          value = 'apply-shim-inherit';
        }
      }
      return value;
    }

    /**
     * "parse" a mixin definition into a map of properties and values
     * cssTextToMap('border: 2px solid black') -> ('border', '2px solid black')
     * @param {string} text
     * @param {boolean=} replaceInitialOrInherit
     * @return {!Object<string, string>}
     */

  }, {
    key: '_cssTextToMap',
    value: function _cssTextToMap(text) {
      var replaceInitialOrInherit = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : false;

      var props = text.split(';');
      var property = void 0,
          value = void 0;
      var out = {};
      for (var i = 0, p, sp; i < props.length; i++) {
        p = props[i];
        if (p) {
          sp = p.split(':');
          // ignore lines that aren't definitions like @media
          if (sp.length > 1) {
            property = sp[0].trim();
            // some properties may have ':' in the value, like data urls
            value = sp.slice(1).join(':');
            if (replaceInitialOrInherit) {
              value = this._replaceInitialOrInherit(property, value);
            }
            out[property] = value;
          }
        }
      }
      return out;
    }

    /**
     * @param {MixinMapEntry} mixinEntry
     */

  }, {
    key: '_invalidateMixinEntry',
    value: function _invalidateMixinEntry(mixinEntry) {
      if (!invalidCallback) {
        return;
      }
      for (var elementName in mixinEntry.dependants) {
        if (elementName !== this._currentElement) {
          invalidCallback(elementName);
        }
      }
    }

    /**
     * @param {string} matchText
     * @param {string} propertyName
     * @param {?string} valueProperty
     * @param {?string} valueMixin
     * @param {!StyleNode} rule
     * @return {string}
     */

  }, {
    key: '_produceCssProperties',
    value: function _produceCssProperties(matchText, propertyName, valueProperty, valueMixin, rule) {
      var _this5 = this;

      // handle case where property value is a mixin
      if (valueProperty) {
        // form: --mixin2: var(--mixin1), where --mixin1 is in the map
        (0, _styleUtil.processVariableAndFallback)(valueProperty, function (prefix, value) {
          if (value && _this5._map.get(value)) {
            valueMixin = '@apply ' + value + ';';
          }
        });
      }
      if (!valueMixin) {
        return matchText;
      }
      var mixinAsProperties = this._consumeCssProperties('' + valueMixin, rule);
      var prefix = matchText.slice(0, matchText.indexOf('--'));
      // `initial` and `inherit` as properties in a map should be replaced because
      // these keywords are eagerly evaluated when the mixin becomes CSS Custom Properties,
      // and would set the variable value, rather than carry the keyword to the `var()` usage.
      var mixinValues = this._cssTextToMap(mixinAsProperties, true);
      var combinedProps = mixinValues;
      var mixinEntry = this._map.get(propertyName);
      var oldProps = mixinEntry && mixinEntry.properties;
      if (oldProps) {
        // NOTE: since we use mixin, the map of properties is updated here
        // and this is what we want.
        combinedProps = Object.assign(Object.create(oldProps), mixinValues);
      } else {
        this._map.set(propertyName, combinedProps);
      }
      var out = [];
      var p = void 0,
          v = void 0;
      // set variables defined by current mixin
      var needToInvalidate = false;
      for (p in combinedProps) {
        v = mixinValues[p];
        // if property not defined by current mixin, set initial
        if (v === undefined) {
          v = 'initial';
        }
        if (oldProps && !(p in oldProps)) {
          needToInvalidate = true;
        }
        out.push('' + propertyName + MIXIN_VAR_SEP + p + ': ' + v);
      }
      if (needToInvalidate) {
        this._invalidateMixinEntry(mixinEntry);
      }
      if (mixinEntry) {
        mixinEntry.properties = combinedProps;
      }
      // because the mixinMap is global, the mixin might conflict with
      // a different scope's simple variable definition:
      // Example:
      // some style somewhere:
      // --mixin1:{ ... }
      // --mixin2: var(--mixin1);
      // some other element:
      // --mixin1: 10px solid red;
      // --foo: var(--mixin1);
      // In this case, we leave the original variable definition in place.
      if (valueProperty) {
        prefix = matchText + ';' + prefix;
      }
      return '' + prefix + out.join('; ') + ';';
    }
  }]);

  return ApplyShim;
}();

/* exports */
/* eslint-disable no-self-assign */


ApplyShim.prototype['detectMixin'] = ApplyShim.prototype.detectMixin;
ApplyShim.prototype['transformStyle'] = ApplyShim.prototype.transformStyle;
ApplyShim.prototype['transformCustomStyle'] = ApplyShim.prototype.transformCustomStyle;
ApplyShim.prototype['transformRules'] = ApplyShim.prototype.transformRules;
ApplyShim.prototype['transformRule'] = ApplyShim.prototype.transformRule;
ApplyShim.prototype['transformTemplate'] = ApplyShim.prototype.transformTemplate;
ApplyShim.prototype['_separator'] = MIXIN_VAR_SEP;
/* eslint-enable no-self-assign */
Object.defineProperty(ApplyShim.prototype, 'invalidCallback', {
  /** @return {?function(string)} */
  get: function get() {
    return invalidCallback;
  },

  /** @param {?function(string)} cb */
  set: function set(cb) {
    invalidCallback = cb;
  }
});

exports.default = ApplyShim;