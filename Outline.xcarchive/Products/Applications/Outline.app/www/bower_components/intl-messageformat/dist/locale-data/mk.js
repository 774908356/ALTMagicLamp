"use strict";

IntlMessageFormat.__addLocaleData({ "locale": "mk", "pluralRuleFunction": function pluralRuleFunction(n, ord) {
    var s = String(n).split("."),
        i = s[0],
        f = s[1] || "",
        v0 = !s[1],
        i10 = i.slice(-1),
        i100 = i.slice(-2),
        f10 = f.slice(-1);if (ord) return i10 == 1 && i100 != 11 ? "one" : i10 == 2 && i100 != 12 ? "two" : (i10 == 7 || i10 == 8) && i100 != 17 && i100 != 18 ? "many" : "other";return v0 && i10 == 1 || f10 == 1 ? "one" : "other";
  } });