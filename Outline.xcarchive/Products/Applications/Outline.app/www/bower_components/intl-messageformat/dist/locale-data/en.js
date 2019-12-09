"use strict";

IntlMessageFormat.__addLocaleData({ "locale": "en", "pluralRuleFunction": function pluralRuleFunction(n, ord) {
    var s = String(n).split("."),
        v0 = !s[1],
        t0 = Number(s[0]) == n,
        n10 = t0 && s[0].slice(-1),
        n100 = t0 && s[0].slice(-2);if (ord) return n10 == 1 && n100 != 11 ? "one" : n10 == 2 && n100 != 12 ? "two" : n10 == 3 && n100 != 13 ? "few" : "other";return n == 1 && v0 ? "one" : "other";
  } });
IntlMessageFormat.__addLocaleData({ "locale": "en-001", "parentLocale": "en" });
IntlMessageFormat.__addLocaleData({ "locale": "en-150", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-AG", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-AI", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-AS", "parentLocale": "en" });
IntlMessageFormat.__addLocaleData({ "locale": "en-AT", "parentLocale": "en-150" });
IntlMessageFormat.__addLocaleData({ "locale": "en-AU", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-BB", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-BE", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-BI", "parentLocale": "en" });
IntlMessageFormat.__addLocaleData({ "locale": "en-BM", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-BS", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-BW", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-BZ", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-CA", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-CC", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-CH", "parentLocale": "en-150" });
IntlMessageFormat.__addLocaleData({ "locale": "en-CK", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-CM", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-CX", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-CY", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-DE", "parentLocale": "en-150" });
IntlMessageFormat.__addLocaleData({ "locale": "en-DG", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-DK", "parentLocale": "en-150" });
IntlMessageFormat.__addLocaleData({ "locale": "en-DM", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-Dsrt", "pluralRuleFunction": function pluralRuleFunction(n, ord) {
    if (ord) return "other";return "other";
  } });
IntlMessageFormat.__addLocaleData({ "locale": "en-ER", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-FI", "parentLocale": "en-150" });
IntlMessageFormat.__addLocaleData({ "locale": "en-FJ", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-FK", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-FM", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-GB", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-GD", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-GG", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-GH", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-GI", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-GM", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-GU", "parentLocale": "en" });
IntlMessageFormat.__addLocaleData({ "locale": "en-GY", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-HK", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-IE", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-IL", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-IM", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-IN", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-IO", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-JE", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-JM", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-KE", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-KI", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-KN", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-KY", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-LC", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-LR", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-LS", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-MG", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-MH", "parentLocale": "en" });
IntlMessageFormat.__addLocaleData({ "locale": "en-MO", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-MP", "parentLocale": "en" });
IntlMessageFormat.__addLocaleData({ "locale": "en-MS", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-MT", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-MU", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-MW", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-MY", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-NA", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-NF", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-NG", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-NL", "parentLocale": "en-150" });
IntlMessageFormat.__addLocaleData({ "locale": "en-NR", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-NU", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-NZ", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-PG", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-PH", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-PK", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-PN", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-PR", "parentLocale": "en" });
IntlMessageFormat.__addLocaleData({ "locale": "en-PW", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-RW", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-SB", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-SC", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-SD", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-SE", "parentLocale": "en-150" });
IntlMessageFormat.__addLocaleData({ "locale": "en-SG", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-SH", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-SI", "parentLocale": "en-150" });
IntlMessageFormat.__addLocaleData({ "locale": "en-SL", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-SS", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-SX", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-SZ", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-Shaw", "pluralRuleFunction": function pluralRuleFunction(n, ord) {
    if (ord) return "other";return "other";
  } });
IntlMessageFormat.__addLocaleData({ "locale": "en-TC", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-TK", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-TO", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-TT", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-TV", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-TZ", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-UG", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-UM", "parentLocale": "en" });
IntlMessageFormat.__addLocaleData({ "locale": "en-US", "parentLocale": "en" });
IntlMessageFormat.__addLocaleData({ "locale": "en-VC", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-VG", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-VI", "parentLocale": "en" });
IntlMessageFormat.__addLocaleData({ "locale": "en-VU", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-WS", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-ZA", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-ZM", "parentLocale": "en-001" });
IntlMessageFormat.__addLocaleData({ "locale": "en-ZW", "parentLocale": "en-001" });