"use strict";

IntlMessageFormat.__addLocaleData({ "locale": "is", "pluralRuleFunction": function pluralRuleFunction(n, ord) {
    var s = String(n).split("."),
        i = s[0],
        t0 = Number(s[0]) == n,
        i10 = i.slice(-1),
        i100 = i.slice(-2);if (ord) return "other";return t0 && i10 == 1 && i100 != 11 || !t0 ? "one" : "other";
  } });