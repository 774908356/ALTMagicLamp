"use strict";

IntlMessageFormat.__addLocaleData({ "locale": "as", "pluralRuleFunction": function pluralRuleFunction(n, ord) {
    if (ord) return n == 1 || n == 5 || n == 7 || n == 8 || n == 9 || n == 10 ? "one" : n == 2 || n == 3 ? "two" : n == 4 ? "few" : n == 6 ? "many" : "other";return n >= 0 && n <= 1 ? "one" : "other";
  } });