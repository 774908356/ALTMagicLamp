"use strict";

IntlMessageFormat.__addLocaleData({ "locale": "pl", "pluralRuleFunction": function pluralRuleFunction(n, ord) {
    var s = String(n).split("."),
        i = s[0],
        v0 = !s[1],
        i10 = i.slice(-1),
        i100 = i.slice(-2);if (ord) return "other";return n == 1 && v0 ? "one" : v0 && i10 >= 2 && i10 <= 4 && (i100 < 12 || i100 > 14) ? "few" : v0 && i != 1 && (i10 == 0 || i10 == 1) || v0 && i10 >= 5 && i10 <= 9 || v0 && i100 >= 12 && i100 <= 14 ? "many" : "other";
  } });