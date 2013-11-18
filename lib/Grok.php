<?php

/**
 * Simple Grok pattern implementation
 * Currently there is NO support for predicates
 *
 * @author kos4live <php-grok@mail.go2inter.net>
 * @see http://code.google.com/p/semicomplete/wiki/Grok
 */
class Grok
{
    protected $pattern_regex = null;
    protected $matchCount = 0;

    protected $patterns = array(
        'USERNAME'      => '[a-zA-Z0-9_-]+',
        'USER'          => '%{USERNAME}',
        'INT'           => '(?:[+-]?(?:[0-9]+))',
        'BASE10NUM'     => '(?<![0-9.+-])(?>[+-]?(?:(?:[0-9]+(?:\.[0-9]+)?)|(?:\.[0-9]+)))',
        'NUMBER'        => '(?:%{BASE10NUM})',
        'BASE16NUM'     => '(?<![0-9A-Fa-f])(?:[+-]?(?:0x)?(?:[0-9A-Fa-f]+))',
        'BASE16FLOAT'   => '\b(?<![0-9A-Fa-f.])(?:[+-]?(?:0x)?(?:(?:[0-9A-Fa-f]+(?:\.[0-9A-Fa-f]*)?)|(?:\.[0-9A-Fa-f]+)))\b',

        'POSINT'        => '\b(?:[1-9][0-9]*)\b',
        'NONNEGINT'     => '\b(?:[0-9]+)\b',
        'WORD'          => '\b\w+\b',
        'NOTSPACE'      => '\S+',
        'SPACE'         => '\s*',
        'DATA'          => '.*?',
        'GREEDYDATA'    => '.*',
        //'QUOTEDSTRING'  => '(?:(?<!\\)(?:"(?:\\.|[^\\"])*"|(?:\'(?:\\.|[^\\\'])*\')|(?:`(?:\\.|[^\\`])*`)))',
        'QUOTEDSTRING'  => '(?:(?<!\\\\)(?:"(?:\\.|[^\\"]+)*"|(?:\'(?:\\.|[^\\\']+)*\')|(?:`(?:\\.|[^\\`]+)*`)))',
        'UUID'          => '[A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}',

        # Networking
        'MAC'           => '(?:%{CISCOMAC}|%{WINDOWSMAC}|%{COMMONMAC})',
        'CISCOMAC'      => '(?:(?:[A-Fa-f0-9]{4}\.){2}[A-Fa-f0-9]{4})',
        'WINDOWSMAC'    => '(?:(?:[A-Fa-f0-9]{2}-){5}[A-Fa-f0-9]{2})',
        'COMMONMAC'     => '(?:(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2})',
        'IP'            => '(?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))(?![0-9])',
        'HOSTNAME'      => '\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(\.?|\b)',
        'HOST'          => '%{HOSTNAME}',
        'IPORHOST'      => '(?:%{HOSTNAME}|%{IP})',
        'HOSTPORT'      => '(?:%{IPORHOST=~/\./}:%{POSINT})',

        # paths
        'PATH'          => '(?:%{UNIXPATH}|%{WINPATH})',
        'UNIXPATH'      => '(?:/(?:[\w_%!$@:.,-]+|\\.)*)+',
        #'UNIXPATH'      => '(?<![\w\/])(?:/[^\/\s?*]*)+',
        'LINUXTTY'      => '(?:/dev/pts/%{NONNEGINT})',
        'BSDTTY'        => '(?:/dev/tty[pq][a-z0-9])',
        'TTY'           => '(?:%{BSDTTY}|%{LINUXTTY})',
        'WINPATH'       => '(?:[A-Za-z]+:|\\)(?:\\[^\\?*]*)+',
        'URIPROTO'      => '[A-Za-z]+(\+[A-Za-z+]+)?',
        'URIHOST'       => '%{IPORHOST}(?::%{POSINT:port})?',
        # uripath comes loosely from RFC1738, but mostly from what Firefox
        # doesn't turn into %XX
        'URIPATH'       => '(?:/[A-Za-z0-9$.+!*\'(){},~:;=#%_-]*)+',
        #'URIPARAM'      => '\?(?:[A-Za-z0-9]+(?:=(?:[^&]*))?(?:&(?:[A-Za-z0-9]+(?:=(?:[^&]*))?)?)*)?'
        'URIPARAM'      => '\?[A-Za-z0-9$.+!*\'|(){},~#%&/=:;_-]*',
        'URIPATHPARAM'  => '%{URIPATH}(?:%{URIPARAM})?',
        'URI'           => '%{URIPROTO}://(?:%{USER}(?::[^@]*)?@)?(?:%{URIHOST})?(?:%{URIPATHPARAM})?',

        # Months: January, Feb, 3, 03, 12, December
        'MONTH'     => '\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\b',
        'MONTHNUM'  => '(?:0?[1-9]|1[0-2])',
        'MONTHDAY'  => '(?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9])',

        # Days: Monday, Tue, Thu, etc...
        'DAY' => '(?:Mon(?:day)?|Tue(?:sday)?|Wed(?:nesday)?|Thu(?:rsday)?|Fri(?:day)?|Sat(?:urday)?|Sun(?:day)?)',

        # Years?
        'YEAR'      => '[0-9]+',
        # Time: HH:MM:SS
        #'TIME'      => '\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?',
        # I'm still on the fence about using grok to perform the time match,
        # since it's probably slower.
        #'TIME'      => '%{POSINT<24}:%{POSINT<60}(?::%{POSINT<60}(?:\.%{POSINT})?)?',
        'HOUR'      => '(?:2[0123]|[01][0-9])',
        'MINUTE'    => '(?:[0-5][0-9])',
        # '60' is a leap second in most time standards and thus is valid.
        'SECOND'    => '(?:(?:[0-5][0-9]|60)(?:[.,][0-9]+)?)',
        'TIME'      => '(?!<[0-9])%{HOUR}:%{MINUTE}(?::%{SECOND})(?![0-9])',
        # datestamp is YYYY/MM/DD-HH:MM:SS.UUUU (or something like it)
        'DATE_US'           => '%{MONTHNUM}[/-]%{MONTHDAY}[/-]%{YEAR}',
        'DATE_EU'           => '%{YEAR}[/-]%{MONTHNUM}[/-]%{MONTHDAY}',
        'ISO8601_TIMEZONE'  => '(?:Z|[+-]%{HOUR}(?::?%{MINUTE}))',
        'ISO8601_SECOND'    => '(?:%{SECOND}|60)',
        'TIMESTAMP_ISO8601' => '%{YEAR}-%{MONTHNUM}-%{MONTHDAY}[T ]%{HOUR}:?%{MINUTE}(?::?%{SECOND})?%{ISO8601_TIMEZONE}?',
        'DATE'              => '%{DATE_US}|%{DATE_EU}',
        'DATESTAMP'         => '%{DATE}[- ]%{TIME}',
        'TZ'                => '(?:[PMCE][SD]T)',
        'DATESTAMP_RFC822'  => '%{DAY} %{MONTH} %{MONTHDAY} %{YEAR} %{TIME} %{TZ}',
        'DATESTAMP_OTHER'   => '%{DAY} %{MONTH} %{MONTHDAY} %{TIME} %{TZ} %{YEAR}',

        # Syslog Dates: Month Day HH:MM:SS
        'SYSLOGTIMESTAMP'   => '%{MONTH} +%{MONTHDAY} %{TIME}',
        'PROG'              => '(?:[\w._/%-]+)',
        'SYSLOGPROG'        => '%{PROG:program}(?:\[%{POSINT:pid}\])?',
        'SYSLOGHOST'        => '%{IPORHOST}',
        'SYSLOGFACILITY'    => '<%{NONNEGINT:facility}.%{NONNEGINT:priority}>',
        'HTTPDATE'          => '%{MONTHDAY}/%{MONTH}/%{YEAR}:%{TIME} %{INT}',

        # Shortcuts
        'QS' => '%{QUOTEDSTRING}',

        # Log formats
        'SYSLOGBASE'        => '%{SYSLOGTIMESTAMP:timestamp} (?:%{SYSLOGFACILITY} )?%{SYSLOGHOST:logsource} %{SYSLOGPROG}:',
        'COMBINEDAPACHELOG' => '%{IPORHOST:clientip} %{USER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:verb} %{URIPATHPARAM:request}(?: HTTP/%{NUMBER:httpversion})?|-)" %{NUMBER:response} (?:%{NUMBER:bytes}|-) "(?:%{URI:referrer}|-)" %{QS:agent}',

        # Log Levels
        'LOGLEVEL'  => '([D|d]ebug|DEBUG|[N|n]otice|NOTICE|[I|i]nfo|INFO|[W|w]arn?(?:ing)?|WARN?(?:ING)?|[E|e]rr?(?:or)?|ERR?(?:OR)?|[C|c]rit?(?:ical)?|CRIT?(?:ICAL)?|[F|f]atal|FATAL|[S|s]evere|SEVERE)',
    );

    protected $fieldMap = array();

    /**
     * Constructor
     *
     * @param array|null $patterns Patterns, overrides original patterns
     */
    public function __construct($patterns = null)
    {
        // Pattern to match %{FOO:bar} or %{FOO<=3}
        // currently no predicate supported
        $this->pattern_regex = "/(?!<\\\\)%\{"
            ."(?<name>"
            .   "(?<pattern>[A-z0-9]+)"
            .   "(?::(?<subname>[A-z0-9_:]+))?"
            .")"
            ."(?:="
            .   "(?<definition>"
            .       "(?:"
            .           "(?P<curly2>\\{(?:(?>[^{}]+|(?>\\\\[{}])+)|(?P>curly2))*\\})+"
            .           "|"
            .           "(?:[^{}]+|\\\\[{}])+"
            .       ")+"
            .   ")"
            .")?"
            ."\\s*(?<predicate>"
            .   "(?:"
            .       "(?P<curly>\\{(?:(?>[^{}]+|(?>\\\\[{}])+)|(?P>curly))*\\})"
            .       "|"
            .       "(?:[^{}]+|\\\\[{}])+"
            .   ")+"
            .")?"
            ."\\}/";

        if (!is_null($patterns)) {
            $this->patterns = $patterns;
        }
    }

    /**
     * Add one additional pattern
     *
     * @param string $name    Name
     * @param string $pattern Pattern
     */
    public function addPattern($name, $pattern)
    {
        $this->patterns[$name] = $pattern;
    }

    /**
     * Add additional patterns.
     * Use array key as name.
     *
     * @param array $patterns Patterns
     */
    public function addPatterns(array $patterns)
    {
        $this->patterns = array_merge($this->patterns, $patterns);
    }

    /**
     * Reset internal data
     */
    protected function reset()
    {
        $this->matchCount = 0;
        $this->fieldMap = array();
    }

    /**
     * Resolve and merge grok pattern
     *
     * @param string $pattern Pattern
     *
     * @return string Merged pattern
     */
    public function resolve($pattern)
    {
        //var_dump('resolve pattern:', $pattern);
        if (preg_match_all($this->pattern_regex, $pattern, $matches, PREG_SET_ORDER)) {
            //var_dump($matches);
            foreach ($matches as $match) {
                $subPattern = $this->resolve($this->patterns[$match['pattern']]);
                if (isset($match['subname']) && !empty($match['subname'])) {
                    //$this->fieldMap[$match['subname']] = ++$this->matchCount; //$subPattern;
                    $this->fieldMap[++$this->matchCount] = $match['subname'];
                    $subPattern = '(?<'.$match['subname'].'>'.$subPattern.')';
                    //var_dump($subPattern);
                }
                $pattern = str_replace($match[0], $subPattern, $pattern, $replaced);
            }
        }
        return $pattern;
    }

    /**
     * Parse given content with pattern.
     * Returns matches as named array.
     *
     * @param string $pattern Pattern to parse content
     * @param string $content Content for parsing
     * @param string $options Options for pattern, for example s (dot all), m (multiline), ... (optional)
     *
     * @return array|bool
     */
    public function parse($pattern, $content, $options = '')
    {
        $results = array();
        $this->reset();
        $pattern = "/".str_replace('/', '\/', $this->resolve($pattern))."/".$options;
        //var_dump('resolved pattern:', $pattern);
        if (preg_match_all($pattern, $content, $matches, PREG_SET_ORDER)) {
            if (count($matches) > 0 && isset($matches[0]) && is_array($matches[0])) {
                foreach ($this->fieldMap as $pos => $key) {
                    if (isset($matches[0][$key])) {
                        $results[$key] = $matches[0][$key];
                    }
                }
            }
        }
        return !empty($results) ? $results : false;
    }
}
