package ess

import (
	"bytes"
	"errors"
)

const countryNone = uint16(0)

func parseCountryCode(b []byte) (uint16, error) {
	b = bytes.TrimSpace(b)
	if bytes.EqualFold(b, []byte("None")) || bytes.EqualFold(b, []byte("Unknown")) {
		return countryNone, nil
	}
	if len(b) != 2 {
		return 0, errors.New("country code must be a two-letter ISO code or None")
	}

	a, z := b[0], b[1]
	if a >= 'a' && a <= 'z' {
		a -= 'a' - 'A'
	}
	if z >= 'a' && z <= 'z' {
		z -= 'a' - 'A'
	}
	if a < 'A' || a > 'Z' || z < 'A' || z > 'Z' {
		return 0, errors.New("country code must be alphabetic")
	}

	return uint16(a)<<8 | uint16(z), nil
}

func countryCode(code uint16) string {
	if code == countryNone {
		return "None"
	}
	return string([]byte{byte(code >> 8), byte(code)})
}

func countryName(code uint16) string {
	if code == countryNone {
		return "Unknown"
	}
	if name, ok := countryNames[code]; ok {
		return name
	}
	return "Unknown"
}

var countryNames = map[uint16]string{
	0x4144: "Andorra",                                      // AD
	0x4145: "United Arab Emirates",                         // AE
	0x4146: "Afghanistan",                                  // AF
	0x4147: "Antigua and Barbuda",                          // AG
	0x4149: "Anguilla",                                     // AI
	0x414C: "Albania",                                      // AL
	0x414D: "Armenia",                                      // AM
	0x414F: "Angola",                                       // AO
	0x4151: "Antarctica",                                   // AQ
	0x4152: "Argentina",                                    // AR
	0x4153: "American Samoa",                               // AS
	0x4154: "Austria",                                      // AT
	0x4155: "Australia",                                    // AU
	0x4157: "Aruba",                                        // AW
	0x4158: "\u00c5land Islands",                           // AX
	0x415A: "Azerbaijan",                                   // AZ
	0x4241: "Bosnia and Herzegovina",                       // BA
	0x4242: "Barbados",                                     // BB
	0x4244: "Bangladesh",                                   // BD
	0x4245: "Belgium",                                      // BE
	0x4246: "Burkina Faso",                                 // BF
	0x4247: "Bulgaria",                                     // BG
	0x4248: "Bahrain",                                      // BH
	0x4249: "Burundi",                                      // BI
	0x424A: "Benin",                                        // BJ
	0x424C: "Saint Barth\u00e9lemy",                        // BL
	0x424D: "Bermuda",                                      // BM
	0x424E: "Brunei",                                       // BN
	0x424F: "Bolivia",                                      // BO
	0x4251: "Bonaire, Sint Eustatius and Saba",             // BQ
	0x4252: "Brazil",                                       // BR
	0x4253: "Bahamas",                                      // BS
	0x4254: "Bhutan",                                       // BT
	0x4256: "Bouvet Island",                                // BV
	0x4257: "Botswana",                                     // BW
	0x4259: "Belarus",                                      // BY
	0x425A: "Belize",                                       // BZ
	0x4341: "Canada",                                       // CA
	0x4343: "Cocos (Keeling) Islands",                      // CC
	0x4344: "DR Congo",                                     // CD
	0x4346: "Central African Republic",                     // CF
	0x4347: "Congo",                                        // CG
	0x4348: "Switzerland",                                  // CH
	0x4349: "C\u00f4te d'Ivoire",                           // CI
	0x434B: "Cook Islands",                                 // CK
	0x434C: "Chile",                                        // CL
	0x434D: "Cameroon",                                     // CM
	0x434E: "China",                                        // CN
	0x434F: "Colombia",                                     // CO
	0x4352: "Costa Rica",                                   // CR
	0x4355: "Cuba",                                         // CU
	0x4356: "Cabo Verde",                                   // CV
	0x4357: "Cura\u00e7ao",                                 // CW
	0x4358: "Christmas Island",                             // CX
	0x4359: "Cyprus",                                       // CY
	0x435A: "Czechia",                                      // CZ
	0x4445: "Germany",                                      // DE
	0x444A: "Djibouti",                                     // DJ
	0x444B: "Denmark",                                      // DK
	0x444D: "Dominica",                                     // DM
	0x444F: "Dominican Republic",                           // DO
	0x445A: "Algeria",                                      // DZ
	0x4543: "Ecuador",                                      // EC
	0x4545: "Estonia",                                      // EE
	0x4547: "Egypt",                                        // EG
	0x4548: "Western Sahara",                               // EH
	0x4552: "Eritrea",                                      // ER
	0x4553: "Spain",                                        // ES
	0x4554: "Ethiopia",                                     // ET
	0x4649: "Finland",                                      // FI
	0x464A: "Fiji",                                         // FJ
	0x464B: "Falkland Islands (Malvinas)",                  // FK
	0x464D: "Micronesia, Federated States of",              // FM
	0x464F: "Faroe Islands",                                // FO
	0x4652: "France",                                       // FR
	0x4741: "Gabon",                                        // GA
	0x4742: "United Kingdom",                               // GB
	0x4744: "Grenada",                                      // GD
	0x4745: "Georgia",                                      // GE
	0x4746: "French Guiana",                                // GF
	0x4747: "Guernsey",                                     // GG
	0x4748: "Ghana",                                        // GH
	0x4749: "Gibraltar",                                    // GI
	0x474C: "Greenland",                                    // GL
	0x474D: "Gambia",                                       // GM
	0x474E: "Guinea",                                       // GN
	0x4750: "Guadeloupe",                                   // GP
	0x4751: "Equatorial Guinea",                            // GQ
	0x4752: "Greece",                                       // GR
	0x4753: "South Georgia and the South Sandwich Islands", // GS
	0x4754: "Guatemala",                                    // GT
	0x4755: "Guam",                                         // GU
	0x4757: "Guinea-Bissau",                                // GW
	0x4759: "Guyana",                                       // GY
	0x484B: "Hong Kong",                                    // HK
	0x484D: "Heard Island and McDonald Islands",            // HM
	0x484E: "Honduras",                                     // HN
	0x4852: "Croatia",                                      // HR
	0x4854: "Haiti",                                        // HT
	0x4855: "Hungary",                                      // HU
	0x4944: "Indonesia",                                    // ID
	0x4945: "Ireland",                                      // IE
	0x494C: "Israel",                                       // IL
	0x494D: "Isle of Man",                                  // IM
	0x494E: "India",                                        // IN
	0x494F: "British Indian Ocean Territory",               // IO
	0x4951: "Iraq",                                         // IQ
	0x4952: "Iran",                                         // IR
	0x4953: "Iceland",                                      // IS
	0x4954: "Italy",                                        // IT
	0x4A45: "Jersey",                                       // JE
	0x4A4D: "Jamaica",                                      // JM
	0x4A4F: "Jordan",                                       // JO
	0x4A50: "Japan",                                        // JP
	0x4B45: "Kenya",                                        // KE
	0x4B47: "Kyrgyzstan",                                   // KG
	0x4B48: "Cambodia",                                     // KH
	0x4B49: "Kiribati",                                     // KI
	0x4B4D: "Comoros",                                      // KM
	0x4B4E: "Saint Kitts and Nevis",                        // KN
	0x4B50: "North Korea",                                  // KP
	0x4B52: "South Korea",                                  // KR
	0x4B57: "Kuwait",                                       // KW
	0x4B59: "Cayman Islands",                               // KY
	0x4B5A: "Kazakhstan",                                   // KZ
	0x4C41: "Laos",                                         // LA
	0x4C42: "Lebanon",                                      // LB
	0x4C43: "Saint Lucia",                                  // LC
	0x4C49: "Liechtenstein",                                // LI
	0x4C4B: "Sri Lanka",                                    // LK
	0x4C52: "Liberia",                                      // LR
	0x4C53: "Lesotho",                                      // LS
	0x4C54: "Lithuania",                                    // LT
	0x4C55: "Luxembourg",                                   // LU
	0x4C56: "Latvia",                                       // LV
	0x4C59: "Libya",                                        // LY
	0x4D41: "Morocco",                                      // MA
	0x4D43: "Monaco",                                       // MC
	0x4D44: "Moldova",                                      // MD
	0x4D45: "Montenegro",                                   // ME
	0x4D46: "Saint Martin (French part)",                   // MF
	0x4D47: "Madagascar",                                   // MG
	0x4D48: "Marshall Islands",                             // MH
	0x4D4B: "North Macedonia",                              // MK
	0x4D4C: "Mali",                                         // ML
	0x4D4D: "Myanmar",                                      // MM
	0x4D4E: "Mongolia",                                     // MN
	0x4D4F: "Macao",                                        // MO
	0x4D50: "Northern Mariana Islands",                     // MP
	0x4D51: "Martinique",                                   // MQ
	0x4D52: "Mauritania",                                   // MR
	0x4D53: "Montserrat",                                   // MS
	0x4D54: "Malta",                                        // MT
	0x4D55: "Mauritius",                                    // MU
	0x4D56: "Maldives",                                     // MV
	0x4D57: "Malawi",                                       // MW
	0x4D58: "Mexico",                                       // MX
	0x4D59: "Malaysia",                                     // MY
	0x4D5A: "Mozambique",                                   // MZ
	0x4E41: "Namibia",                                      // NA
	0x4E43: "New Caledonia",                                // NC
	0x4E45: "Niger",                                        // NE
	0x4E46: "Norfolk Island",                               // NF
	0x4E47: "Nigeria",                                      // NG
	0x4E49: "Nicaragua",                                    // NI
	0x4E4C: "Netherlands",                                  // NL
	0x4E4F: "Norway",                                       // NO
	0x4E50: "Nepal",                                        // NP
	0x4E52: "Nauru",                                        // NR
	0x4E55: "Niue",                                         // NU
	0x4E5A: "New Zealand",                                  // NZ
	0x4F4D: "Oman",                                         // OM
	0x5041: "Panama",                                       // PA
	0x5045: "Peru",                                         // PE
	0x5046: "French Polynesia",                             // PF
	0x5047: "Papua New Guinea",                             // PG
	0x5048: "Philippines",                                  // PH
	0x504B: "Pakistan",                                     // PK
	0x504C: "Poland",                                       // PL
	0x504D: "Saint Pierre and Miquelon",                    // PM
	0x504E: "Pitcairn",                                     // PN
	0x5052: "Puerto Rico",                                  // PR
	0x5053: "Palestine",                                    // PS
	0x5054: "Portugal",                                     // PT
	0x5057: "Palau",                                        // PW
	0x5059: "Paraguay",                                     // PY
	0x5141: "Qatar",                                        // QA
	0x5245: "R\u00e9union",                                 // RE
	0x524F: "Romania",                                      // RO
	0x5253: "Serbia",                                       // RS
	0x5255: "Russia",                                       // RU
	0x5257: "Rwanda",                                       // RW
	0x5341: "Saudi Arabia",                                 // SA
	0x5342: "Solomon Islands",                              // SB
	0x5343: "Seychelles",                                   // SC
	0x5344: "Sudan",                                        // SD
	0x5345: "Sweden",                                       // SE
	0x5347: "Singapore",                                    // SG
	0x5348: "Saint Helena, Ascension and Tristan da Cunha", // SH
	0x5349: "Slovenia",                                     // SI
	0x534A: "Svalbard and Jan Mayen",                       // SJ
	0x534B: "Slovakia",                                     // SK
	0x534C: "Sierra Leone",                                 // SL
	0x534D: "San Marino",                                   // SM
	0x534E: "Senegal",                                      // SN
	0x534F: "Somalia",                                      // SO
	0x5352: "Suriname",                                     // SR
	0x5353: "South Sudan",                                  // SS
	0x5354: "Sao Tome and Principe",                        // ST
	0x5356: "El Salvador",                                  // SV
	0x5358: "Sint Maarten (Dutch part)",                    // SX
	0x5359: "Syria",                                        // SY
	0x535A: "Eswatini",                                     // SZ
	0x5443: "Turks and Caicos Islands",                     // TC
	0x5444: "Chad",                                         // TD
	0x5446: "French Southern Territories",                  // TF
	0x5447: "Togo",                                         // TG
	0x5448: "Thailand",                                     // TH
	0x544A: "Tajikistan",                                   // TJ
	0x544B: "Tokelau",                                      // TK
	0x544C: "Timor-Leste",                                  // TL
	0x544D: "Turkmenistan",                                 // TM
	0x544E: "Tunisia",                                      // TN
	0x544F: "Tonga",                                        // TO
	0x5452: "T\u00fcrkiye",                                 // TR
	0x5454: "Trinidad and Tobago",                          // TT
	0x5456: "Tuvalu",                                       // TV
	0x5457: "Taiwan",                                       // TW
	0x545A: "Tanzania",                                     // TZ
	0x5541: "Ukraine",                                      // UA
	0x5547: "Uganda",                                       // UG
	0x554D: "United States Minor Outlying Islands",         // UM
	0x5553: "United States",                                // US
	0x5559: "Uruguay",                                      // UY
	0x555A: "Uzbekistan",                                   // UZ
	0x5641: "Vatican City",                                 // VA
	0x5643: "Saint Vincent and the Grenadines",             // VC
	0x5645: "Venezuela",                                    // VE
	0x5647: "Virgin Islands, British",                      // VG
	0x5649: "Virgin Islands, U.S.",                         // VI
	0x564E: "Vietnam",                                      // VN
	0x5655: "Vanuatu",                                      // VU
	0x5746: "Wallis and Futuna",                            // WF
	0x5753: "Samoa",                                        // WS
	0x5945: "Yemen",                                        // YE
	0x5954: "Mayotte",                                      // YT
	0x5A41: "South Africa",                                 // ZA
	0x5A4D: "Zambia",                                       // ZM
	0x5A57: "Zimbabwe",                                     // ZW
	0x4555: "European Union",                               // EU
	0x584B: "Kosovo",                                       // XK
	0x5A5A: "Unknown",                                      // ZZ
}
