"use strict";

IntlMessageFormat.__addLocaleData({ "locale": "mt", "pluralRuleFunction": function pluralRuleFunction(n, ord) {
    var s = String(n).split("."),
        t0 = Number(s[0]) == n,
        n100 = t0 && s[0].slice(-2);if (ord) return "other";return n == 1 ? "one" : n == 0 || n100 >= 2 && n100 <= 10 ? "few" : n100 >= 11 && n100 <= 19 ? "many" : "other";
  } });