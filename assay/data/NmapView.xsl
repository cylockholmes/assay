<?xml version="1.0" encoding="utf-8"?>
<!--
Nmap Bootstrap XSL
This software must not be used by military or secret service organisations.
Andreas Hontzia (@honze_net) & LRVT (@l4rm4nd) & Fabian Kopp (@dreizehnutters)
-->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
<xsl:key name="serviceGroup" match="host/ports/port[state/@state='open' and service/@name]" use="concat(            substring('ssl/', 1, (service/@tunnel = 'ssl') * string-length('ssl/')),            service/@name,            '-',            @protocol          )"/>
  <xsl:key name="uniquePorts" match="port[state/@state='open']" use="@portid"/>
  <xsl:key name="openPortProtocolGroup" match="host/ports/port[state/@state='open']" use="concat(@portid, '-', @protocol)"/>
  <xsl:key name="rareServiceGroup" match="host/ports/port[state/@state='open' and service/@name]" use="concat(            substring('ssl/', 1, count(script[@id='ssl-cert']) * string-length('ssl/')),            substring(service/@name, 1, string-length(service/@name) * (number(service/@conf) &gt; 5)),            substring('unknown', 1, string-length('unknown') * not(number(service/@conf) &gt; 5)),            '-',            @protocol          )"/>
  <xsl:key name="httpServiceBucketGroup" match="host/ports/port[state/@state='open' and service/@name and (contains(translate(service/@name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'http') or script[@id='http-title'] or script[@id='http-headers'] or script[@id='http-server-header'])]" use="concat(substring('ssl/', 1, count(script[@id='ssl-cert']) * string-length('ssl/')), substring(service/@name, 1, string-length(service/@name) * (number(service/@conf) &gt; 5)), substring('unknown', 1, string-length('unknown') * not(number(service/@conf) &gt; 5)), '|', normalize-space(service/@product), '|', substring(normalize-space(service/@version), 1, string-length(normalize-space(service/@version)) * boolean(string(normalize-space(service/@product)))))"/>
  <xsl:output method="html" encoding="utf-8" indent="yes" doctype-system="about:legacy-compat"/>

  <xsl:template name="render-hostname-or-na">
    <xsl:param name="hostname"/>
    <xsl:choose>
      <xsl:when test="string(normalize-space($hostname)) != ''">
        <xsl:value-of select="normalize-space($hostname)"/>
      </xsl:when>
      <xsl:otherwise>N/A</xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="render-ipv4-sort-key">
    <xsl:param name="address"/>
    <xsl:variable name="octet-1" select="substring-before($address, '.')"/>
    <xsl:variable name="rest-1" select="substring-after($address, '.')"/>
    <xsl:variable name="octet-2" select="substring-before($rest-1, '.')"/>
    <xsl:variable name="rest-2" select="substring-after($rest-1, '.')"/>
    <xsl:variable name="octet-3" select="substring-before($rest-2, '.')"/>
    <xsl:variable name="octet-4" select="substring-after($rest-2, '.')"/>
    <xsl:value-of select="concat(
      '4-',
      format-number(number($octet-1), '000'),
      '.',
      format-number(number($octet-2), '000'),
      '.',
      format-number(number($octet-3), '000'),
      '.',
      format-number(number($octet-4), '000')
    )"/>
  </xsl:template>

  <xsl:template name="render-address-sort-key">
    <xsl:param name="address"/>
    <xsl:variable name="normalized-address" select="normalize-space($address)"/>
    <xsl:choose>
      <xsl:when test="string($normalized-address) = '' or $normalized-address = 'N/A'">
        <xsl:text></xsl:text>
      </xsl:when>
      <xsl:when test="contains($normalized-address, '.') and not(contains($normalized-address, ':'))">
        <xsl:call-template name="render-ipv4-sort-key">
          <xsl:with-param name="address" select="$normalized-address"/>
        </xsl:call-template>
      </xsl:when>
      <xsl:when test="contains($normalized-address, ':')">
        <xsl:value-of select="concat('6-', translate($normalized-address, 'ABCDEF', 'abcdef'))"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="concat('z-', translate($normalized-address, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'))"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="extract-first-dns-name">
    <xsl:param name="text"/>
    <xsl:variable name="normalized-text" select="normalize-space($text)"/>
    <xsl:choose>
      <xsl:when test="contains($normalized-text, 'DNS:')">
        <xsl:variable name="after-dns" select="substring-after($normalized-text, 'DNS:')"/>
        <xsl:variable name="candidate-raw">
          <xsl:choose>
            <xsl:when test="contains($after-dns, ',')">
              <xsl:value-of select="substring-before($after-dns, ',')"/>
            </xsl:when>
            <xsl:otherwise>
              <xsl:value-of select="$after-dns"/>
            </xsl:otherwise>
          </xsl:choose>
        </xsl:variable>
        <xsl:variable name="candidate" select="normalize-space($candidate-raw)"/>
        <xsl:variable name="remaining">
          <xsl:choose>
            <xsl:when test="contains($after-dns, ',')">
              <xsl:value-of select="substring-after($after-dns, ',')"/>
            </xsl:when>
            <xsl:otherwise/>
          </xsl:choose>
        </xsl:variable>
        <xsl:choose>
          <xsl:when test="string($candidate) != '' and $candidate != 'localhost' and string(translate($candidate, '0123456789.:-[]', '')) != ''">
            <xsl:value-of select="$candidate"/>
          </xsl:when>
          <xsl:otherwise>
            <xsl:call-template name="extract-first-dns-name">
              <xsl:with-param name="text" select="$remaining"/>
            </xsl:call-template>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:when>
      <xsl:otherwise/>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="extract-url-host">
    <xsl:param name="url"/>
    <xsl:variable name="normalized-url" select="normalize-space($url)"/>
    <xsl:variable name="without-scheme">
      <xsl:choose>
        <xsl:when test="contains($normalized-url, '://')">
          <xsl:value-of select="substring-after($normalized-url, '://')"/>
        </xsl:when>
        <xsl:otherwise>
          <xsl:value-of select="$normalized-url"/>
        </xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <xsl:variable name="without-path">
      <xsl:choose>
        <xsl:when test="contains($without-scheme, '/')">
          <xsl:value-of select="substring-before($without-scheme, '/')"/>
        </xsl:when>
        <xsl:otherwise>
          <xsl:value-of select="$without-scheme"/>
        </xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <xsl:variable name="without-query">
      <xsl:choose>
        <xsl:when test="contains($without-path, '?')">
          <xsl:value-of select="substring-before($without-path, '?')"/>
        </xsl:when>
        <xsl:otherwise>
          <xsl:value-of select="$without-path"/>
        </xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <xsl:variable name="without-fragment">
      <xsl:choose>
        <xsl:when test="contains($without-query, '#')">
          <xsl:value-of select="substring-before($without-query, '#')"/>
        </xsl:when>
        <xsl:otherwise>
          <xsl:value-of select="$without-query"/>
        </xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <xsl:variable name="host-only">
      <xsl:choose>
        <xsl:when test="starts-with($without-fragment, '[') and contains($without-fragment, ']')">
          <xsl:value-of select="substring-before(substring-after($without-fragment, '['), ']')"/>
        </xsl:when>
        <xsl:when test="contains($without-fragment, ':')">
          <xsl:value-of select="substring-before($without-fragment, ':')"/>
        </xsl:when>
        <xsl:otherwise>
          <xsl:value-of select="$without-fragment"/>
        </xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <xsl:variable name="candidate" select="normalize-space($host-only)"/>
    <xsl:if test="string($candidate) != '' and $candidate != 'localhost' and string(translate($candidate, '0123456789.:-[]', '')) != ''">
      <xsl:value-of select="$candidate"/>
    </xsl:if>
  </xsl:template>

  <xsl:template name="resolve-inferred-hostname">
    <xsl:variable name="location-url">
      <xsl:choose>
        <xsl:when test="string(ancestor-or-self::host[1]/ports/port[script[@id='http-title']/elem[@key='redirect_url']][1]/script[@id='http-title']/elem[@key='redirect_url']) != ''">
          <xsl:value-of select="ancestor-or-self::host[1]/ports/port[script[@id='http-title']/elem[@key='redirect_url']][1]/script[@id='http-title']/elem[@key='redirect_url']"/>
        </xsl:when>
        <xsl:when test="contains(ancestor-or-self::host[1]/ports/port[script[@id='http-headers']][1]/script[@id='http-headers']/@output, 'Location:')">
          <xsl:call-template name="extract-header-value">
            <xsl:with-param name="text" select="ancestor-or-self::host[1]/ports/port[script[@id='http-headers']][1]/script[@id='http-headers']/@output"/>
            <xsl:with-param name="label" select="'Location'"/>
          </xsl:call-template>
        </xsl:when>
        <xsl:when test="contains(ancestor-or-self::host[1]/ports/port[script[@id='http-headers']][1]/script[@id='http-headers']/@output, 'location:')">
          <xsl:call-template name="extract-header-value">
            <xsl:with-param name="text" select="ancestor-or-self::host[1]/ports/port[script[@id='http-headers']][1]/script[@id='http-headers']/@output"/>
            <xsl:with-param name="label" select="'location'"/>
          </xsl:call-template>
        </xsl:when>
        <xsl:when test="contains(ancestor-or-self::host[1]/ports/port[script[@id='fingerprint-strings']][1]/script[@id='fingerprint-strings']/elem[@key='GetRequest'], 'Location:')">
          <xsl:call-template name="extract-header-value">
            <xsl:with-param name="text" select="ancestor-or-self::host[1]/ports/port[script[@id='fingerprint-strings']][1]/script[@id='fingerprint-strings']/elem[@key='GetRequest']"/>
            <xsl:with-param name="label" select="'Location'"/>
          </xsl:call-template>
        </xsl:when>
        <xsl:when test="contains(ancestor-or-self::host[1]/ports/port[script[@id='fingerprint-strings']][1]/script[@id='fingerprint-strings']/elem[@key='GetRequest'], 'location:')">
          <xsl:call-template name="extract-header-value">
            <xsl:with-param name="text" select="ancestor-or-self::host[1]/ports/port[script[@id='fingerprint-strings']][1]/script[@id='fingerprint-strings']/elem[@key='GetRequest']"/>
            <xsl:with-param name="label" select="'location'"/>
          </xsl:call-template>
        </xsl:when>
        <xsl:otherwise/>
      </xsl:choose>
    </xsl:variable>
    <xsl:variable name="location-host">
      <xsl:call-template name="extract-url-host">
        <xsl:with-param name="url" select="$location-url"/>
      </xsl:call-template>
    </xsl:variable>
    <xsl:value-of select="$location-host"/>
  </xsl:template>

  <xsl:template name="resolve-inferred-hostname-source">
    <xsl:variable name="location-url">
      <xsl:choose>
        <xsl:when test="string(ancestor-or-self::host[1]/ports/port[script[@id='http-title']/elem[@key='redirect_url']][1]/script[@id='http-title']/elem[@key='redirect_url']) != ''">
          <xsl:value-of select="ancestor-or-self::host[1]/ports/port[script[@id='http-title']/elem[@key='redirect_url']][1]/script[@id='http-title']/elem[@key='redirect_url']"/>
        </xsl:when>
        <xsl:otherwise/>
      </xsl:choose>
    </xsl:variable>
    <xsl:choose>
      <xsl:when test="string($location-url) != ''">
        <xsl:text>inferred-location</xsl:text>
      </xsl:when>
      <xsl:otherwise/>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="resolve-effective-hostname">
    <xsl:value-of select="normalize-space(ancestor-or-self::host[1]/hostnames/hostname[1]/@name)"/>
  </xsl:template>

  <xsl:template name="resolve-effective-hostname-source">
    <xsl:value-of select="normalize-space(ancestor-or-self::host[1]/hostnames/hostname[1]/@type)"/>
  </xsl:template>

  <xsl:template name="extract-last-token">
    <xsl:param name="text"/>
    <xsl:variable name="normalized-text" select="normalize-space($text)"/>
    <xsl:choose>
      <xsl:when test="contains($normalized-text, ' ')">
        <xsl:call-template name="extract-last-token">
          <xsl:with-param name="text" select="substring-after($normalized-text, ' ')"/>
        </xsl:call-template>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="$normalized-text"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="render-onlinehosts-link">
    <xsl:param name="address"/>
    <a>
      <xsl:attribute name="href">
        <xsl:text>#onlinehosts-</xsl:text>
        <xsl:value-of select="translate($address, '.:', '--')"/>
      </xsl:attribute>
      <xsl:value-of select="$address"/>
    </a>
  </xsl:template>

  <xsl:template name="render-service-name">
    <xsl:choose>
      <xsl:when test="script[@id='ssl-cert']">
        <xsl:text>ssl/</xsl:text>
        <xsl:choose>
          <xsl:when test="number(service/@conf) &gt; 5">
            <xsl:value-of select="service/@name"/>
          </xsl:when>
          <xsl:otherwise>unknown</xsl:otherwise>
        </xsl:choose>
      </xsl:when>
      <xsl:otherwise>
        <xsl:choose>
          <xsl:when test="number(service/@conf) &gt; 5">
            <xsl:value-of select="service/@name"/>
          </xsl:when>
          <xsl:otherwise>unknown</xsl:otherwise>
        </xsl:choose>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="render-external-link">
    <xsl:param name="href"/>
    <xsl:param name="text"/>
    <a target="_blank" rel="noopener noreferrer">
      <xsl:attribute name="href">
        <xsl:value-of select="$href"/>
      </xsl:attribute>
      <xsl:value-of select="$text"/>
    </a>
  </xsl:template>

  <xsl:template name="render-endpoint-host">
    <xsl:param name="host"/>
    <xsl:variable name="normalized-host" select="normalize-space($host)"/>
    <xsl:choose>
      <xsl:when test="contains($normalized-host, ':') and not(starts-with($normalized-host, '[')) and not(contains($normalized-host, ']'))">
        <xsl:text>[</xsl:text>
        <xsl:value-of select="$normalized-host"/>
        <xsl:text>]</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="$normalized-host"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="render-endpoint-link">
    <xsl:param name="address"/>
    <xsl:param name="port"/>
    <xsl:param name="protocol" select="'tcp'"/>
    <xsl:param name="service-name" select="''"/>
    <xsl:param name="tunnel" select="''"/>
    <xsl:param name="text" select="''"/>
    <xsl:param name="class" select="'endpoint-link'"/>
    <xsl:variable name="normalized-address" select="normalize-space($address)"/>
    <xsl:variable name="normalized-port" select="normalize-space($port)"/>
    <xsl:variable name="normalized-text" select="normalize-space($text)"/>
    <xsl:variable name="normalized-service" select="translate(normalize-space($service-name), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')"/>
    <xsl:variable name="normalized-protocol" select="translate(normalize-space($protocol), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')"/>
    <xsl:variable name="scheme">
      <xsl:choose>
        <xsl:when test="$tunnel = 'ssl' or starts-with($normalized-service, 'ssl/') or contains($normalized-service, 'https')">https</xsl:when>
        <xsl:otherwise>http</xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <xsl:variable name="formatted-host">
      <xsl:call-template name="render-endpoint-host">
        <xsl:with-param name="host" select="$normalized-address"/>
      </xsl:call-template>
    </xsl:variable>
    <xsl:choose>
      <xsl:when test="string($normalized-address) != '' and string($normalized-port) != ''">
        <a target="_blank" rel="noopener noreferrer">
          <xsl:if test="string(normalize-space($class)) != ''">
            <xsl:attribute name="class">
              <xsl:value-of select="$class"/>
            </xsl:attribute>
          </xsl:if>
          <xsl:attribute name="href">
            <xsl:value-of select="concat($scheme, '://', $formatted-host, ':', $normalized-port)"/>
          </xsl:attribute>
          <xsl:choose>
            <xsl:when test="string($normalized-text) != ''">
              <xsl:value-of select="$normalized-text"/>
            </xsl:when>
            <xsl:otherwise>
              <xsl:value-of select="$normalized-port"/>
            </xsl:otherwise>
          </xsl:choose>
        </a>
      </xsl:when>
      <xsl:when test="string($normalized-text) != ''">
        <xsl:value-of select="$normalized-text"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="$normalized-port"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="render-nvd-cpe-link">
    <xsl:param name="cpe"/>
    <a class="cpe-copy" title="Click to copy CPE">
      <xsl:attribute name="href">
        <xsl:text>https://nvd.nist.gov/vuln/search/results?form_type=Advanced&amp;cves=on&amp;cpe_version=</xsl:text>
        <xsl:value-of select="$cpe"/>
      </xsl:attribute>
      <xsl:attribute name="data-cpe">
        <xsl:value-of select="$cpe"/>
      </xsl:attribute>
      <xsl:value-of select="$cpe"/>
    </a>
  </xsl:template>

  <xsl:template name="render-cpe-text">
    <xsl:param name="cpe"/>
    <xsl:choose>
      <xsl:when test="normalize-space($cpe) != '' and normalize-space($cpe) != 'unknown'">
        <a class="cpe-inline-link" target="_blank" rel="noopener noreferrer" title="Open CPE details in PentestFactory">
          <xsl:attribute name="href">
            <xsl:text>https://cve.pentestfactory.de/?cpe=</xsl:text>
            <xsl:value-of select="$cpe"/>
          </xsl:attribute>
          <span aria-hidden="true">⌕</span>
        </a>
      </xsl:when>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="render-certificate-row">
    <xsl:param name="label"/>
    <xsl:param name="primary"/>
    <xsl:param name="secondary" select="''"/>
    <xsl:param name="row-class" select="''"/>
    <xsl:param name="value-class" select="''"/>
    <xsl:param name="data-valid-from" select="''"/>
    <xsl:param name="data-valid-to" select="''"/>
    <xsl:if test="string($primary) != '' or string($secondary) != ''">
      <div>
        <xsl:attribute name="class">
          <xsl:text>certificate-row</xsl:text>
          <xsl:if test="string($row-class) != ''">
            <xsl:text> </xsl:text>
            <xsl:value-of select="$row-class"/>
          </xsl:if>
        </xsl:attribute>
        <span class="certificate-label">
          <xsl:value-of select="$label"/>
          <xsl:text>: </xsl:text>
        </span>
        <i>
          <xsl:attribute name="class">
            <xsl:text>certificate-value</xsl:text>
            <xsl:if test="string($value-class) != ''">
              <xsl:text> </xsl:text>
              <xsl:value-of select="$value-class"/>
            </xsl:if>
          </xsl:attribute>
          <xsl:if test="string($data-valid-from) != ''">
            <xsl:attribute name="data-valid-from">
              <xsl:value-of select="$data-valid-from"/>
            </xsl:attribute>
          </xsl:if>
          <xsl:if test="string($data-valid-to) != ''">
            <xsl:attribute name="data-valid-to">
              <xsl:value-of select="$data-valid-to"/>
            </xsl:attribute>
          </xsl:if>
          <xsl:value-of select="$primary"/>
          <xsl:if test="string($secondary) != ''">
            <xsl:text> – </xsl:text>
            <xsl:value-of select="$secondary"/>
          </xsl:if>
        </i>
      </div>
    </xsl:if>
  </xsl:template>

  <xsl:template name="extract-header-value">
    <xsl:param name="text"/>
    <xsl:param name="label"/>
    <xsl:variable name="needle" select="concat($label, ':')"/>
    <xsl:choose>
      <xsl:when test="contains($text, $needle)">
        <xsl:value-of select="normalize-space(substring-before(substring-after($text, $needle), '&#xA;'))"/>
      </xsl:when>
      <xsl:otherwise/>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="extract-powered-by-value">
    <xsl:param name="text"/>
    <xsl:variable name="lower-text" select="translate($text, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')"/>
    <xsl:variable name="needle" select="'powered-by:'"/>
    <xsl:choose>
      <xsl:when test="contains($lower-text, $needle)">
        <xsl:variable name="prefix-length" select="string-length(substring-before($lower-text, $needle))"/>
        <xsl:variable name="value-start" select="$prefix-length + string-length($needle) + 1"/>
        <xsl:value-of select="normalize-space(substring-before(concat(substring($text, $value-start), '&#xA;'), '&#xA;'))"/>
      </xsl:when>
      <xsl:otherwise/>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="extract-stack-hint-line">
    <xsl:param name="text"/>
    <xsl:if test="string($text) != ''">
      <xsl:variable name="line" select="normalize-space(substring-before(concat($text, '&#xA;'), '&#xA;'))"/>
      <xsl:variable name="rest" select="substring-after($text, '&#xA;')"/>
      <xsl:variable name="lower-line" select="translate($line, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')"/>
      <xsl:choose>
        <xsl:when test="contains($lower-line, 'powered') or contains($lower-line, 'php') or contains($lower-line, 'asp')">
          <xsl:value-of select="$line"/>
        </xsl:when>
        <xsl:otherwise>
          <xsl:call-template name="extract-stack-hint-line">
            <xsl:with-param name="text" select="$rest"/>
          </xsl:call-template>
        </xsl:otherwise>
      </xsl:choose>
    </xsl:if>
  </xsl:template>

  <xsl:template name="normalize-powered-by-stack">
    <xsl:param name="value"/>
    <xsl:variable name="lower-value" select="translate(normalize-space($value), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')"/>
    <xsl:variable name="has-php" select="contains($lower-value, 'php/') or contains($lower-value, 'php')"/>
    <xsl:variable name="php-version">
      <xsl:choose>
        <xsl:when test="contains($lower-value, 'php/')">
          <xsl:variable name="prefix-length" select="string-length(substring-before($lower-value, 'php/'))"/>
          <xsl:variable name="value-start" select="$prefix-length + 5"/>
          <xsl:variable name="php-rest" select="substring(normalize-space($value), $value-start)"/>
          <xsl:value-of select="normalize-space(substring-before(concat(translate($php-rest, ',;()[]', '      '), ' '), ' '))"/>
        </xsl:when>
        <xsl:otherwise/>
      </xsl:choose>
    </xsl:variable>
    <xsl:variable name="has-aspnet" select="contains($lower-value, 'asp.net core') or contains($lower-value, 'asp.net') or contains($lower-value, 'aspnet') or contains($lower-value, 'asp')"/>
    <xsl:if test="$has-php">
      <xsl:text>PHP</xsl:text>
      <xsl:if test="string($php-version) != ''">
        <xsl:text> </xsl:text>
        <xsl:value-of select="$php-version"/>
      </xsl:if>
    </xsl:if>
    <xsl:if test="$has-aspnet">
      <xsl:if test="$has-php">
        <xsl:text>, </xsl:text>
      </xsl:if>
      <xsl:choose>
        <xsl:when test="contains($lower-value, 'asp.net core') or contains($lower-value, 'aspnetcore')">
          <xsl:text>ASP.NET Core</xsl:text>
        </xsl:when>
        <xsl:otherwise>
          <xsl:text>ASP.NET</xsl:text>
        </xsl:otherwise>
      </xsl:choose>
    </xsl:if>
  </xsl:template>

  <xsl:template name="render-http-row">
    <xsl:param name="label"/>
    <xsl:param name="value"/>
    <xsl:if test="string($value) != ''">
      <div class="certificate-row">
        <span class="certificate-label">
          <xsl:value-of select="$label"/>
          <xsl:text>: </xsl:text>
        </span>
        <i class="certificate-value">
          <xsl:value-of select="$value"/>
        </i>
      </div>
    </xsl:if>
  </xsl:template>

  <xsl:template name="render-service-url">
    <xsl:param name="scheme"/>
    <xsl:param name="host"/>
    <xsl:param name="port"/>
    <xsl:variable name="formatted-host">
      <xsl:call-template name="render-endpoint-host">
        <xsl:with-param name="host" select="$host"/>
      </xsl:call-template>
    </xsl:variable>
    <xsl:call-template name="render-external-link">
      <xsl:with-param name="href" select="concat($scheme, '://', $formatted-host, ':', $port)"/>
      <xsl:with-param name="text" select="concat($scheme, '://', $formatted-host, ':', $port)"/>
    </xsl:call-template>
  </xsl:template>

  <xsl:template name="render-host-header-label">
    <xsl:param name="address"/>
    <xsl:param name="mac" select="''"/>
    <xsl:param name="vendor" select="''"/>
    <xsl:param name="hostname" select="''"/>
    <xsl:value-of select="$address"/>
    <xsl:if test="string($mac) != ''">
      <xsl:text> (</xsl:text>
      <xsl:value-of select="$mac"/>
      <xsl:if test="string($vendor) != ''">
        <xsl:text> - </xsl:text>
        <xsl:value-of select="$vendor"/>
      </xsl:if>
      <xsl:text>)</xsl:text>
    </xsl:if>
    <xsl:if test="string($hostname) != ''">
      <xsl:text> - </xsl:text>
      <xsl:value-of select="$hostname"/>
    </xsl:if>
  </xsl:template>

  <xsl:template name="render-script-output-list">
    <xsl:if test="count(script) &gt; 0">
      <ul class="list-unstyled mb-0">
        <xsl:for-each select="script">
          <li>
            <strong>
              <xsl:value-of select="@id"/>
            </strong>
            <pre class="bg-light p-2 rounded">
              <xsl:value-of select="@output"/>
            </pre>
          </li>
        </xsl:for-each>
      </ul>
    </xsl:if>
  </xsl:template>

  <xsl:template name="render-empty-state">
    <xsl:param name="message"/>
    <p class="text-muted fst-italic mb-3">
      <xsl:value-of select="$message"/>
    </p>
  </xsl:template>

<xsl:template name="render-head">
      <head>
        <meta name="referrer" content="no-referrer"/>
        <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='14' fill='%23f7f9fb'/%3E%3Ccircle cx='27' cy='27' r='15' fill='none' stroke='%2324313d' stroke-width='6'/%3E%3Cpath d='M38 38 L52 52' stroke='%2324313d' stroke-width='6' stroke-linecap='round'/%3E%3C/svg%3E"/>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet"/>
        <link href="https://cdn.datatables.net/v/bs5/jq-3.7.0/jszip-3.10.1/dt-2.3.7/b-3.2.6/b-colvis-3.2.6/b-html5-3.2.6/b-print-3.2.6/fh-4.0.5/datatables.min.css" rel="stylesheet" crossorigin="anonymous"/>
        <script src="https://cdn.datatables.net/v/bs5/jq-3.7.0/jszip-3.10.1/dt-2.3.7/b-3.2.6/b-colvis-3.2.6/b-html5-3.2.6/b-print-3.2.6/fh-4.0.5/datatables.min.js" crossorigin="anonymous"/>
        <xsl:call-template name="render-visualization-head-assets"/>
        <style><![CDATA[
:root {
  --report-page-bg: #eef2f5;
  --report-surface: #f7f9fb;
  --report-surface-muted: #e6ebf0;
  --report-surface-hover: #edf3f8;
  --report-border: #cfd8e3;
  --report-border-strong: #bcc8d6;
  --report-shadow: 0 0.35rem 1rem rgba(72, 94, 116, 0.08);
}

html,
body {
  background: var(--report-page-bg);
}

body {
  color: #24313d;
}

body.report-initializing {
  overflow: hidden;
  height: 100vh;
}

.report-loading-overlay {
  position: fixed;
  inset: 0;
  z-index: 2000;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 1.5rem;
  background: rgba(238, 242, 245, 0.72);
  backdrop-filter: blur(6px);
  transition: opacity 0.2s ease, visibility 0.2s ease;
}

.report-loading-overlay-no-blur {
  background: rgba(238, 242, 245, 0.36);
  backdrop-filter: none;
}

.report-loading-overlay.is-hidden {
  opacity: 0;
  visibility: hidden;
  pointer-events: none;
}

.report-loading-card {
  min-width: min(100%, 18rem);
  padding: 1rem 1.1rem;
  border: 1px solid var(--report-border);
  border-radius: 0.8rem;
  background: var(--report-surface);
  box-shadow: var(--report-shadow);
  text-align: center;
}

.report-loading-title {
  margin: 0;
  font-size: 0.98rem;
  font-weight: 700;
  color: #24313d;
}

.report-loading-dots {
  display: inline-flex;
  align-items: center;
  gap: 0.16rem;
  margin-left: 0.18rem;
  vertical-align: middle;
}

.report-loading-dot {
  width: 0.26rem;
  height: 0.26rem;
  border-radius: 999px;
  background: currentColor;
  opacity: 0.22;
  animation: report-loading-dot-pulse 1.05s infinite ease-in-out;
}

.report-loading-dot:nth-child(2) {
  animation-delay: 0.16s;
}

.report-loading-dot:nth-child(3) {
  animation-delay: 0.32s;
}

@keyframes report-loading-dot-pulse {
  0%,
  80%,
  100% {
    opacity: 0.22;
    transform: translateY(0);
  }

  40% {
    opacity: 0.9;
    transform: translateY(-0.08rem);
  }
}

@media (prefers-reduced-motion: reduce) {
  .report-loading-dot {
    animation: none;
    opacity: 0.55;
    transform: none;
  }
}

#reportContent {
  width: 100%;
  max-width: 100%;
  min-width: 0;
  padding-top: 5.5rem;
}

a {
  text-decoration: none !important;
}

.endpoint-link {
  color: inherit;
  white-space: nowrap;
  text-decoration: none;
}

.host-list {
  display: grid;
  gap: 1rem;
}

.service-inventory-hosts-cell {
  min-width: 18rem;
}

#service-inventory {
  width: 100% !important;
}

#service-inventory thead th,
#service-inventory tbody td {
  text-align: left;
}

#service-inventory thead th {
  width: 100%;
}

#service-inventory tbody tr > td {
  --service-inventory-row-bg: var(--report-surface);
  --service-inventory-row-bg-muted: #eef3f7;
  --service-inventory-row-bg-soft: rgba(238, 243, 247, 0.92);
  --service-inventory-nested-bg: var(--service-inventory-row-bg);
  --service-inventory-nested-bg-soft: var(--service-inventory-row-bg-soft);
}

#service-inventory.table-striped > tbody > tr:nth-of-type(odd) > td {
  --service-inventory-row-bg: #eef3f7;
  --service-inventory-row-bg-muted: var(--report-surface);
  --service-inventory-row-bg-soft: rgba(247, 249, 251, 0.94);
  --service-inventory-nested-bg: var(--service-inventory-row-bg);
  --service-inventory-nested-bg-soft: var(--service-inventory-row-bg-soft);
}

#table-services thead th:last-child,
#table-services tbody td.open-service-details-cell,
#table-services tbody td.open-service-details-cell * {
  text-align: left;
}

#table-services thead th:last-child,
#table-services tbody td.open-service-details-cell {
  width: 16rem;
  max-width: 16rem;
}

#table-services tbody td.open-service-details-cell {
  white-space: normal;
  word-break: break-word;
  overflow-wrap: anywhere;
}

.service-inventory-service-details {
  border: 1px solid var(--report-border);
  border-radius: 0.55rem;
  background: var(--service-inventory-row-bg);
  overflow: hidden;
}

.service-inventory-service-summary {
  cursor: pointer;
  list-style: none;
  padding: 0.55rem 0.7rem;
  display: flex;
  align-items: flex-start;
  gap: 0.45rem;
}

.service-inventory-service-summary::-webkit-details-marker {
  display: none;
}

.service-inventory-service-summary::before {
  content: "▸";
  color: #3f5f74;
  font-size: 0.95rem;
  line-height: 1.2;
  flex: 0 0 auto;
  transform-origin: center;
  transition: transform 0.16s ease;
}

.service-inventory-service-details[open] .service-inventory-service-summary::before {
  transform: rotate(90deg);
}

.service-inventory-service-summary {
  background: var(--service-inventory-row-bg-muted);
}

.service-inventory-summary-line {
  display: flex;
  flex-wrap: wrap;
  gap: 0.25rem 0.7rem;
  align-items: baseline;
}

.service-inventory-service-title {
  font-weight: 600;
  color: #24313d;
  overflow-wrap: anywhere;
}

.service-inventory-service-meta {
  color: #5b6977;
  font-size: 0.92rem;
  overflow-wrap: anywhere;
}

.service-inventory-service-body {
  padding: 0.55rem 0.7rem 0.7rem;
}

.service-inventory-host-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.9rem;
  table-layout: fixed;
}

.service-inventory-host-table-wrapper .dt-buttons,
.service-inventory-host-table-wrapper .dataTables_filter,
.service-inventory-host-table-wrapper .dt-search {
  margin-bottom: 0.45rem;
}

.service-inventory-host-table-wrapper .dt-buttons .btn,
.service-inventory-host-table-wrapper .dt-buttons .dt-button {
  padding: 0.2rem 0.45rem;
  font-size: 0.72rem;
}

.service-inventory-host-table th,
.service-inventory-host-table td {
  padding: 0.35rem 0.45rem;
  border-top: 1px solid rgba(188, 200, 214, 0.7);
  vertical-align: middle;
  text-align: left;
  overflow-wrap: anywhere;
}

.service-inventory-host-table thead th {
  border-top: 0;
  color: #5b6977;
  font-size: 0.82rem;
  font-weight: 600;
  background: var(--service-inventory-row-bg-soft);
}

.service-inventory-host-table tbody tr:first-child td {
  border-top: 0;
}

.service-inventory-host-table tbody tr.service-inventory-variant-band-even td {
  background: rgba(247, 249, 251, 0.94);
}

.service-inventory-host-table tbody tr.service-inventory-variant-band-odd td {
  background: rgba(238, 243, 247, 0.94);
}

.service-inventory-host-table tbody tr.service-inventory-product-separator td {
  border-top: 0.22rem solid var(--report-border-strong);
}

.service-inventory-host-table tbody tr.service-inventory-variant-separator td {
  border-top: 0.14rem solid rgba(188, 200, 214, 0.95);
}

.service-inventory-host-bucket-column {
  width: 40%;
}

.service-inventory-host-column {
  width: 10%;
}

.service-inventory-host-ports-column {
  width: 10%;
}

.service-inventory-host-service-column {
  width: 40%;
}

.service-inventory-host-link {
  color: #0a58ca;
  overflow-wrap: anywhere;
}

.service-inventory-bucket-label {
  color: #24313d;
  display: inline-flex;
  font-weight: 500;
  overflow-wrap: anywhere;
  text-decoration: none;
}

.service-inventory-bucket-label:hover,
.service-inventory-bucket-label:focus-visible {
  color: #0a58ca;
  text-decoration: underline;
}

.service-inventory-script-list {
  display: grid;
  gap: 0.45rem;
}

.service-inventory-script-group-details {
  display: block;
}

.service-inventory-script-group-summary {
  cursor: pointer;
  list-style: none;
  color: #4f5e6d;
  font-size: 0.82rem;
  font-weight: 600;
  padding: 0.35rem 0.45rem;
  border: 1px solid rgba(188, 200, 214, 0.7);
  border-radius: 0.45rem;
  background: var(--service-inventory-nested-bg-soft);
}

.service-inventory-script-group-summary::-webkit-details-marker {
  display: none;
}

.service-inventory-script-group-summary::before {
  content: "▸";
  display: inline-block;
  margin-right: 0.3rem;
  color: #3f5f74;
  transition: transform 0.16s ease;
}

.service-inventory-script-group-details[open] .service-inventory-script-group-summary::before {
  transform: rotate(90deg);
}

.service-inventory-script-group-body {
  margin-top: 0.45rem;
}

.service-inventory-extra-info-details {
  display: grid;
  gap: 0.55rem;
}

.service-inventory-extra-info-block {
  display: grid;
  gap: 0.18rem;
  padding: 0.45rem 0.55rem;
  border: 1px solid rgba(188, 200, 214, 0.7);
  border-radius: 0.45rem;
  background: var(--service-inventory-nested-bg-soft);
}

.service-inventory-extra-info-port-label {
  color: #4f5e6d;
  font-size: 0.78rem;
  font-weight: 600;
}

.service-inventory-extra-info-value {
  color: #24313d;
  white-space: normal;
  overflow-wrap: anywhere;
}

.service-inventory-http-details {
  display: grid;
  gap: 0.55rem;
}

.service-inventory-http-block {
  display: grid;
  gap: 0.18rem;
  padding: 0.45rem 0.55rem;
  border: 1px solid rgba(188, 200, 214, 0.7);
  border-radius: 0.45rem;
  background: var(--service-inventory-nested-bg-soft);
}

.service-inventory-http-port-label {
  color: #4f5e6d;
  font-size: 0.78rem;
  font-weight: 600;
}

.service-inventory-http-row {
  display: flex;
  gap: 0.35rem;
  align-items: flex-start;
}

.service-inventory-http-label {
  color: #4f5e6d;
  font-size: 0.78rem;
  font-weight: 600;
  flex: 0 0 auto;
}

.service-inventory-http-value {
  color: #24313d;
  font-size: 0.78rem;
  min-width: 0;
  overflow-wrap: anywhere;
}

.service-inventory-vulners {
  display: grid;
  gap: 0.35rem;
  margin-top: 0.55rem;
  padding: 0.45rem 0.55rem;
  border: 1px solid rgba(188, 200, 214, 0.7);
  border-radius: 0.45rem;
  background: var(--service-inventory-nested-bg-soft);
}

.service-inventory-vulners-summary {
  color: #4f5e6d;
  font-size: 0.78rem;
  font-weight: 600;
}

.service-inventory-vulners-list {
  display: grid;
  gap: 0.25rem;
}

.service-inventory-vulners-item {
  display: flex;
  flex-wrap: wrap;
  gap: 0.3rem;
  align-items: baseline;
  font-size: 0.78rem;
}

.service-inventory-vulners-item strong {
  color: #4f5e6d;
}

.service-inventory-vulners-more {
  color: #6c757d;
  font-size: 0.75rem;
}

.service-inventory-script-item-details {
  display: block;
}

.service-inventory-script-item-summary {
  cursor: pointer;
  list-style: none;
  color: #4f5e6d;
  font-size: 0.78rem;
  font-weight: 600;
  overflow-wrap: anywhere;
  display: flex;
  align-items: center;
  gap: 0.4rem;
  flex-wrap: wrap;
  padding: 0.35rem 0.45rem;
  border: 1px solid rgba(188, 200, 214, 0.7);
  border-radius: 0.45rem;
  background: var(--service-inventory-nested-bg-soft);
}

.service-inventory-script-item-summary::-webkit-details-marker {
  display: none;
}

.service-inventory-script-item-summary::before {
  content: "▸";
  display: inline-block;
  margin-right: 0.3rem;
  color: #3f5f74;
  transition: transform 0.16s ease;
}

.service-inventory-script-item-details[open] .service-inventory-script-item-summary::before {
  transform: rotate(90deg);
}

.service-inventory-script-item {
  display: grid;
  gap: 0.15rem;
}

.service-inventory-script-label {
  color: #4f5e6d;
  font-size: 0.78rem;
  font-weight: 600;
  overflow-wrap: anywhere;
}

.service-inventory-script-output {
  margin: 0.35rem 0 0;
  padding: 0.45rem 0.55rem;
  color: #24313d;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
  font-size: 0.78rem;
  line-height: 1.35;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  border: 1px solid rgba(188, 200, 214, 0.7);
  border-radius: 0.45rem;
  background: var(--service-inventory-nested-bg);
}

.service-inventory-empty {
  margin: 0;
  color: #6c757d;
}

.host-entry {
  border: 1px solid var(--report-border);
  border-radius: 0.5rem;
  background: var(--report-surface);
  box-shadow: 0 0.125rem 0.4rem rgba(72, 94, 116, 0.08);
  overflow: hidden;
}

.host-list .host-entry:nth-child(even) {
  background: #f3f7fb;
}

.host-entry-summary {
  cursor: pointer;
  padding: 1rem 1.25rem;
  background: var(--report-surface-muted);
  font-weight: 600;
  position: relative;
}

.host-list .host-entry:nth-child(even) .host-entry-summary {
  background: #dfe8f0;
}

.host-entry-anchor {
  position: absolute;
  left: 0;
  top: -4rem;
  visibility: hidden;
  width: 0;
  height: 0;
}

.host-entry-label {
  display: inline;
}

.host-entry-body {
  padding: 1.25rem;
}

.certificate-block {
  display: grid;
  gap: 0.2rem;
  max-width: 20rem;
}

.certificate-row {
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  line-height: 1.3;
}

.certificate-label {
  font-weight: 600;
}

.certificate-value {
  display: inline;
}

.certificate-expiry-value {
  display: inline-flex;
  align-items: center;
  gap: 0.45rem;
  flex-wrap: wrap;
  max-width: 100%;
}

.certificate-expiry-row {
  display: flex;
  align-items: flex-start;
  gap: 0.35rem;
  white-space: normal;
  overflow: visible;
  text-overflow: clip;
}

.certificate-expiry-row .certificate-label {
  flex: 0 0 auto;
}

.certificate-expiry-row .certificate-expiry-value {
  flex: 1 1 auto;
  min-width: 0;
}

.certificate-expiry-badge {
  display: inline-flex;
  align-items: center;
  border-radius: 999px;
  padding: 0.15rem 0.55rem;
  font-size: 0.72rem;
  font-style: normal;
  font-weight: 700;
  letter-spacing: 0.01em;
  line-height: 1.2;
  white-space: nowrap;
  border: 1px solid transparent;
}

.certificate-expiry-badge.is-valid {
  background: #e8f5e9;
  border-color: #b7dfbd;
  color: #1f6f43;
}

.certificate-expiry-badge.is-expiring {
  background: #fff3cd;
  border-color: #f3d58a;
  color: #8a5a00;
}

.certificate-expiry-badge.is-expired {
  background: #f8d7da;
  border-color: #ecb5bc;
  color: #a61e2f;
}

.certificate-expiry-badge.is-long-lived {
  background: #fff0db;
  border-color: #e9c896;
  color: #8a5a00;
}

.certificate-expiry-badge.is-self-signed {
  background: #eef1f4;
  border-color: #cfd6de;
  color: #495057;
}

.http-title-block {
  max-width: 20rem;
}

.http-title-value {
  display: block;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.http-details-block {
  display: grid;
  gap: 0.2rem;
  max-width: 26rem;
}

.service-extra-http {
  margin-top: 0.35rem;
}

.summary-command {
  margin: 1rem 0 0;
  border: 1px solid var(--report-border);
  border-radius: 0.5rem;
  background: rgba(247, 249, 251, 0.84);
}

.summary-command summary {
  cursor: pointer;
  padding: 0.75rem 1rem;
  color: #6c757d;
  font-size: 0.95rem;
  font-weight: 600;
}

.summary-command pre {
  margin: 0;
  padding: 0 1rem 1rem;
  font-size: 0.9rem;
  background: transparent;
  border: 0;
  color: #495057;
  white-space: pre-wrap;
  word-wrap: break-word;
}

.summary-progress {
  height: 1.75rem;
  font-size: 0.95rem;
  overflow: visible;
}

.summary-progress .progress-bar {
  font-weight: 600;
  white-space: nowrap;
  overflow: visible;
  padding: 0 0.45rem;
  min-width: max-content;
  justify-content: center;
}

.summary-progress .progress-bar.bg-warning {
  color: #212529;
}

.summary-card-link {
  display: block;
  color: inherit;
}

.summary-card-link:hover,
.summary-card-link:focus-visible {
  color: inherit;
}

.summary-card {
  border: 1px solid var(--report-border);
  border-radius: 0.85rem;
  background: var(--report-page-bg);
  height: 100%;
  padding: 1rem;
  transition: transform 0.16s ease, box-shadow 0.16s ease, border-color 0.16s ease;
}

.summary-card-label {
  color: #5f6e7d;
  font-size: 0.84rem;
  font-weight: 600;
  letter-spacing: 0.01em;
  line-height: 1.3;
}

.summary-card-value {
  margin-top: 0.2rem;
  font-size: 1.85rem;
  font-weight: 600;
  line-height: 1.15;
  color: #24313d;
}

.summary-card.is-clickable {
  cursor: pointer;
}

.summary-card-link:hover .summary-card,
.summary-card-link:focus-visible .summary-card {
  transform: translateY(-1px);
  box-shadow: 0 0.45rem 1rem rgba(72, 94, 116, 0.12);
  border-color: var(--report-border-strong);
}

.summary-toolbar {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  gap: 1rem;
  margin-top: 1rem;
  align-items: center;
}

.host-scope-controls {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.75rem;
}

.host-scope-label {
  color: #334150;
  font-size: 0.9rem;
  font-weight: 700;
}

.host-scope-summary {
  color: #5f6e7d;
  font-size: 0.88rem;
}

.host-scope-column,
.host-scope-cell {
  width: 1%;
  white-space: nowrap;
  text-align: center;
}

#table-overview tbody tr.host-scope-excluded {
  opacity: 0.55;
}

#table-overview tbody tr.host-scope-excluded .host-scope-checkbox {
  opacity: 1;
}

.summary-note {
  margin: 0.85rem 0 0;
  color: #5f6e7d;
  font-size: 0.9rem;
  line-height: 1.45;
}

.summary-note-icon {
  display: inline;
  color: #3f5f74;
  font-size: 0.95rem;
  font-weight: 600;
  line-height: 1;
  margin-right: 0.25rem;
}

.footer-spacer {
  border: 0;
  height: 0;
  margin: 1rem 0 0.8rem;
  opacity: 0;
}

.footer {
  border-top: 1px solid var(--report-border);
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.72);
}

.density-controls {
  display: inline-flex;
  align-items: center;
  gap: 0.75rem;
}

.density-controls-label {
  font-size: 0.82rem;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: #6c757d;
  white-space: nowrap;
}

.density-toggle-group .btn {
  min-width: 7rem;
}

body.report-density-comfortable .table {
  font-size: 0.95rem;
  line-height: 1.4;
}

body.report-density-comfortable .table > :not(caption) > * > * {
  padding-top: 0.75rem;
  padding-bottom: 0.75rem;
}

body.report-density-dense .table {
  font-size: 0.86rem;
  line-height: 1.2;
}

body.report-density-dense .table > :not(caption) > * > * {
  padding-top: 0.3rem;
  padding-bottom: 0.3rem;
  padding-left: 0.45rem;
  padding-right: 0.45rem;
}

body.report-density-dense .table .badge {
  font-size: 0.72rem;
}

body.report-density-dense .host-entry-summary {
  padding: 0.8rem 1rem;
  font-size: 0.95rem;
}

body.report-density-dense .service-inventory-service-summary {
  padding: 0.45rem 0.6rem;
}

body.report-density-dense .service-inventory-service-body {
  padding: 0.45rem 0.6rem 0.6rem;
}

body.report-density-dense .host-entry-body {
  padding: 0.8rem;
}

body.report-density-dense .summary-command summary {
  padding: 0.55rem 0.85rem;
  font-size: 0.85rem;
}

body.report-density-dense .summary-command pre {
  padding: 0 0.85rem 0.85rem;
  font-size: 0.82rem;
}

.vulners-summary {
  cursor: pointer;
  color: #495057;
  font-weight: 600;
}

.vulners-summary::-webkit-details-marker {
  display: none;
}

.vulners-list {
  margin-top: 0.5rem;
}

.cpe-copy {
  cursor: copy;
}

.cpe-copy.copied {
  color: #0a58ca !important;
}

.clipboard-feedback {
  position: fixed;
  right: 1rem;
  bottom: 1rem;
  z-index: 1085;
  max-width: min(22rem, calc(100vw - 2rem));
  padding: 0.55rem 0.8rem;
  border-radius: 0.6rem;
  background: rgba(33, 37, 41, 0.92);
  color: #f8f9fa;
  font-size: 0.88rem;
  font-weight: 600;
  box-shadow: 0 0.8rem 1.8rem rgba(15, 23, 42, 0.22);
  opacity: 0;
  transform: translateY(0.45rem);
  pointer-events: none;
  transition: opacity 140ms ease, transform 140ms ease;
}

.clipboard-feedback.is-visible {
  opacity: 1;
  transform: translateY(0);
}

.clipboard-feedback.is-error {
  background: rgba(139, 0, 0, 0.94);
}

.cpe-inline-link {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 1.4rem;
  min-height: 1.4rem;
  font-size: 1.15rem;
  line-height: 1;
  color: #4f5e6d;
  text-decoration: none;
}

.cpe-inline-link:hover,
.cpe-inline-link:focus {
  color: #0a58ca;
}

.keyword-highlight-controls {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
  align-items: center;
  margin-top: 1rem;
}

.keyword-highlight-controls .form-control {
  flex: 1 1 20rem;
  min-width: 16rem;
}

.keyword-highlight-controls .btn-warning {
  background-color: #e9ecef;
  border-color: #ced4da;
  color: #212529;
}

.keyword-highlight-controls .btn-warning:hover,
.keyword-highlight-controls .btn-warning:focus,
.keyword-highlight-controls .btn-warning:active {
  background-color: #dde1e5;
  border-color: #c6cbd1;
  color: #212529;
}

.keyword-highlight-mark {
  background: #fff3a3;
  color: inherit;
  padding: 0 0.15em;
  border-radius: 0.2rem;
}

.datatable-inline-filter {
  display: inline-flex;
  align-items: center;
  gap: 0.55rem;
  margin-left: 0.85rem;
}

.datatable-inline-filter-label {
  margin: 0;
  font-size: inherit;
  font-weight: inherit;
  color: inherit;
  white-space: nowrap;
}

.datatable-inline-filter .form-select {
  min-width: 11rem;
}

.datatable-reset-button {
  line-height: 1.2;
}

.datatable-filter-active {
  border-color: #198754 !important;
  box-shadow: 0 0 0 0.18rem rgba(25, 135, 84, 0.16);
}

.dtfh-floatingparenthead {
  z-index: 1020 !important;
}

.dtfh-floatingparenthead table {
  margin-top: 0 !important;
  background: var(--report-surface);
}

#mainNavbar {
  border-bottom: 1px solid var(--report-border);
  background: rgba(247, 249, 251, 0.94) !important;
  backdrop-filter: saturate(140%) blur(10px);
}

#summary,
#scannedhosts,
#openservices,
#serviceinventory,
#onlinehosts {
  scroll-margin-top: 5.5rem;
}

#reportContent > hr.my-4 {
  margin-top: 3.35rem !important;
  margin-bottom: 1.35rem !important;
  border: 0;
  height: 2px;
  border-radius: 999px;
  opacity: 1;
  background: linear-gradient(90deg, rgba(120, 144, 168, 0), rgba(120, 144, 168, 0.52), rgba(173, 186, 200, 0.48), rgba(120, 144, 168, 0.52), rgba(120, 144, 168, 0));
  box-shadow: 0 0 0 1px rgba(110, 132, 154, 0.06), 0 0.35rem 0.9rem rgba(110, 132, 154, 0.10);
}

#reportContent > h2.bg-light.rounded,
#summary.bg-light,
footer.footer.bg-light {
  background: var(--report-surface) !important;
}

#summary {
  border: 1px solid var(--report-border);
  box-shadow: var(--report-shadow);
  margin-top: 0 !important;
  margin-bottom: 3rem !important;
}

#reportContent > h2.bg-light.rounded {
  border: 1px solid var(--report-border);
  box-shadow: 0 0.15rem 0.56rem rgba(72, 94, 116, 0.075);
}

.section-heading-title {
  display: block;
  color: #24313d;
  font-weight: 600;
  line-height: 1.2;
}

.section-heading-subtitle {
  display: block;
  margin-top: 0.35rem;
  color: #637282;
  font-size: 0.92rem;
  font-weight: 400;
  line-height: 1.4;
}

.table {
  --bs-table-bg: var(--report-surface);
  --bs-table-striped-bg: #eef3f7;
  --bs-table-hover-bg: var(--report-surface-hover);
  --bs-table-border-color: var(--report-border);
  color: #24313d;
}

.table-light,
.table > thead.table-light,
.table > thead.table-light > tr > th,
.table > thead.table-light > tr > td {
  --bs-table-bg: var(--report-surface-muted);
  --bs-table-border-color: var(--report-border);
  background: var(--report-surface-muted) !important;
  color: #24313d;
}

.table-responsive {
  background: transparent;
  border: 0;
  border-radius: 0;
  box-shadow: none;
}

.table-responsive > .dt-container,
.table-responsive > table {
  background: var(--report-surface);
  border: 1px solid var(--report-border);
  border-radius: 0.75rem;
  box-shadow: var(--report-shadow);
}

.table-responsive > .dt-container {
  padding: 0.85rem 0.9rem 0.7rem;
}

.datatable-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
  flex-wrap: wrap;
  margin-bottom: 0.85rem;
}

.datatable-toolbar-start,
.datatable-toolbar-center,
.datatable-toolbar-end {
  display: flex;
  align-items: center;
  flex: 1 1 14rem;
  min-width: 0;
}

.datatable-toolbar-start {
  justify-content: flex-start;
}

.datatable-toolbar-center {
  justify-content: center;
}

.datatable-toolbar-end {
  justify-content: flex-end;
}

.datatable-toolbar-center .dataTables_filter,
.datatable-toolbar-center .dt-search {
  display: inline-flex;
  align-items: center;
  gap: 0.45rem;
  margin: 0;
}

.datatable-toolbar-center .dataTables_filter label,
.datatable-toolbar-center .dt-search label {
  display: inline-flex;
  align-items: center;
  gap: 0.45rem;
  margin: 0;
  white-space: nowrap;
}

.datatable-toolbar-center .dataTables_filter input,
.datatable-toolbar-center .dt-search input {
  min-width: min(100%, 18rem);
  margin: 0;
}

.datatable-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
  flex-wrap: wrap;
}

.datatable-footer-start,
.datatable-footer-end {
  display: flex;
  align-items: center;
}

.datatable-footer-start {
  justify-content: flex-start;
  gap: 0.75rem;
  flex-wrap: wrap;
}

.datatable-footer-end {
  justify-content: flex-end;
}

.table-responsive > .dt-container .table {
  margin-bottom: 0.75rem;
}

.keyword-highlight-controls .form-control {
  background: var(--report-surface);
  border-color: var(--report-border);
}

.navbar-about-trigger {
  display: inline-flex;
  align-items: center;
  gap: 0.55rem;
  border: 0;
  background: transparent;
  cursor: pointer;
  font-weight: 600;
  color: #24313d;
}

.navbar-about-trigger:hover,
.navbar-about-trigger:focus-visible {
  background: rgba(13, 110, 253, 0.08);
}

.navbar-about-trigger-label {
  white-space: nowrap;
}

.navbar-brand-mark-lens {
  opacity: 0.58;
}

.report-dialog {
  width: min(100% - 2rem, 53rem);
  max-width: 53rem;
  border: 1px solid var(--report-border);
  border-radius: 0.95rem;
  padding: 0;
  background: var(--report-surface);
  color: #24313d;
  box-shadow: 0 1rem 2.5rem rgba(72, 94, 116, 0.24);
}

.report-dialog::backdrop {
  background: rgba(36, 49, 61, 0.4);
  backdrop-filter: blur(3px);
}

.report-dialog-shell {
  display: grid;
}

.report-dialog-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  padding: 1rem 1.15rem;
}

.report-dialog-header {
  border-bottom: 1px solid var(--report-border);
}

.report-dialog-title {
  margin: 0;
  font-size: 1.05rem;
  font-weight: 700;
}

.report-dialog-subtitle {
  margin: 0.2rem 0 0;
  color: #334150;
  font-size: 0.9rem;
  font-weight: 600;
}

.report-dialog-body {
  padding: 1rem 1.15rem 1.1rem;
}

.report-dialog-lead {
  margin: 0;
  color: #334150;
  line-height: 1.55;
}

.report-dialog-note {
  margin: 0.45rem 0 0;
  color: #6f7d8b;
  font-size: 0.78rem;
  line-height: 1.35;
}

.report-dialog-note-kbd {
  font-size: inherit;
  padding: 0.08rem 0.28rem;
}

.report-dialog-meta {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin: 0.7rem 0 0;
  color: #5f6e7d;
  font-size: 0.9rem;
}

.report-dialog-version-link {
  color: #0a58ca;
  font-weight: 600;
  text-decoration: none;
}

.report-dialog-version-link:hover,
.report-dialog-version-link:focus-visible {
  text-decoration: underline;
}

.report-dialog-meta-separator {
  color: #8a97a5;
}

.report-dialog-section {
  margin-top: 1.1rem;
}

.report-dialog-section-title {
  margin: 0 0 0.7rem;
  font-size: 0.95rem;
  font-weight: 700;
}

.report-source-list {
  display: grid;
  gap: 0.75rem;
}

.report-source-item {
  padding: 0.85rem 0.95rem;
  border: 1px solid var(--report-border);
  border-radius: 0.75rem;
  background: var(--report-surface-muted);
}

.report-source-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
}

.report-source-name {
  font-weight: 600;
  color: #24313d;
  text-decoration: none;
}

.report-source-name:hover,
.report-source-name:focus-visible {
  color: #0a58ca;
}

.report-source-note {
  margin: 0.45rem 0 0;
  color: #5f6e7d;
  font-size: 0.9rem;
  line-height: 1.45;
}

.report-license-badge {
  display: inline-flex;
  align-items: center;
  border-radius: 999px;
  padding: 0.2rem 0.6rem;
  background: #dbe8ff;
  border: 1px solid #b5cef9;
  color: #0a58ca;
  font-size: 0.75rem;
  font-weight: 700;
  white-space: nowrap;
}

#mainNavbar .container-fluid {
  display: flex;
  align-items: center;
  overflow-x: auto;
  scrollbar-width: thin;
  gap: 0.75rem;
  flex-wrap: nowrap;
}

#navbarNav .navbar-nav.me-auto .nav-link {
  display: inline-flex;
  align-items: center;
  min-height: 3.45rem;
  padding: 0.75rem 1.2rem;
  border-radius: 0.75rem;
  font-weight: 500;
}

#navbarNav .navbar-nav.me-auto .nav-link:hover,
#navbarNav .navbar-nav.me-auto .nav-link:focus-visible {
  background: rgba(13, 110, 253, 0.08);
}

#navbarNav .navbar-nav.me-auto .nav-link.is-active {
  background: rgba(13, 110, 253, 0.14);
  color: #0a58ca;
  box-shadow: inset 0 0 0 1px rgba(13, 110, 253, 0.12);
}

#navbarNav {
  width: 100%;
  display: flex !important;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
  flex-wrap: nowrap;
  min-width: max-content;
}

#navbarNav .navbar-nav {
  flex-direction: row;
  flex-wrap: nowrap;
  gap: 0.25rem;
  min-width: max-content;
}

@media (max-width: 991.98px) {
  #mainNavbar .container-fluid {
    gap: 0.5rem;
  }

  #navbarNav {
    gap: 0.5rem;
  }

  #navbarNav .navbar-nav.me-auto .nav-link {
    min-height: 2.75rem;
    padding: 0.45rem 0.8rem;
    font-size: 0.92rem;
    border-radius: 0.6rem;
  }

  #navbarNav .navbar-nav.ms-auto .nav-link {
    padding: 0.35rem 0.55rem;
  }

  .navbar-about-trigger {
    gap: 0.4rem;
  }

  .navbar-about-trigger-label {
    font-size: 0.92rem;
  }

  .report-dialog {
    width: min(100% - 1rem, 48rem);
  }

  .report-dialog-header {
    padding-left: 0.9rem;
    padding-right: 0.9rem;
  }

  .report-dialog-body {
    padding-left: 0.9rem;
    padding-right: 0.9rem;
  }

  .report-source-top {
    align-items: flex-start;
    flex-direction: column;
  }

  .datatable-toolbar-start,
  .datatable-toolbar-center,
  .datatable-toolbar-end,
  .datatable-footer-start,
  .datatable-footer-end {
    flex: 1 1 100%;
    justify-content: flex-start;
  }

}
        ]]></style>
        <xsl:call-template name="render-visualization-styles"/>
        <title>NmapView | Analysis Interface</title>
      </head>
  </xsl:template>
  <xsl:template name="render-loading-overlay">
        <div id="reportLoadingOverlay" class="report-loading-overlay report-loading-overlay-no-blur" role="status" aria-live="polite" aria-label="Loading report">
          <div class="report-loading-card">
            <p class="report-loading-title"><span id="reportLoadingTitleText">Preparing Report</span><span class="report-loading-dots" aria-hidden="true"><span class="report-loading-dot"/><span class="report-loading-dot"/><span class="report-loading-dot"/></span></p>
          </div>
        </div>
  </xsl:template>
  <xsl:template name="render-navbar">
        <nav id="mainNavbar" class="navbar navbar-light bg-light fixed-top">
          <div class="container-fluid">
            <div id="navbarNav">
              <ul class="navbar-nav me-auto">
                <li class="nav-item">
                  <a class="nav-link" href="#summary">Summary</a>
                </li>
                <li class="nav-item">
                  <a class="nav-link" href="#scannedhosts">Host Overview</a>
                </li>
                <li class="nav-item">
                  <a class="nav-link" href="#openservices">Open Services</a>
                </li>
                <li class="nav-item">
                  <a class="nav-link" href="#serviceinventory">Service Summary</a>
                </li>
                <li class="nav-item">
                  <a class="nav-link" href="#onlinehosts">Host Details</a>
                </li>
              </ul>
              <ul class="navbar-nav ms-auto">
                <li class="nav-item">
                  <button
                    type="button"
                    class="nav-link navbar-about-trigger"
                    id="aboutDialogTrigger"
                    aria-haspopup="dialog"
                    aria-controls="aboutDialog"
                    aria-label="Get NmapView source and licenses"
                    title="Get NmapView source"
                  >
                    <span class="navbar-about-trigger-label">NmapView</span>
                    <svg class="navbar-brand-mark" height="64" width="64" viewBox="0 0 64 64" aria-hidden="true" style="max-height: 42px; width: auto;">
                      <rect width="64" height="64" rx="14" fill="#f7f9fb"/>
                      <circle class="navbar-brand-mark-lens" cx="27" cy="27" r="15" fill="none" stroke="#24313d" stroke-width="6"/>
                      <path class="navbar-brand-mark-lens" d="M38 38 L52 52" stroke="#24313d" stroke-width="6" stroke-linecap="round"/>
                    </svg>
                  </button>
                </li>
              </ul>
            </div>
          </div>
        </nav>
  </xsl:template>
  <xsl:template name="render-about-dialog">
        <dialog id="aboutDialog" class="report-dialog" aria-labelledby="aboutDialogTitle">
          <div class="report-dialog-shell">
            <div class="report-dialog-header">
              <div>
                <h2 id="aboutDialogTitle" class="report-dialog-title">About NmapView</h2>
                <p class="report-dialog-subtitle">Analysis stays local in the report and no scan data is sent anywhere.</p>
              </div>
              <button type="button" class="btn-close report-dialog-close" data-dialog-close="aboutDialog" aria-label="Close"></button>
            </div>
            <div class="report-dialog-body">
              <p class="report-dialog-lead">NmapView turns Nmap XML into a single interactive HTML analysis report. It helps you review hosts, open services, service variants, script output, and visualizations in one portable file.</p>
              <p class="report-dialog-note">Tip: Press <kbd class="report-dialog-note-kbd">/</kbd> to search the active table</p>
              <p class="report-dialog-note">Tip: Click port numbers to open the endpoint in a new browser tab.</p>
              <p class="report-dialog-note">Note: Service names are treated as reliable when Nmap reports <code>service/@conf &gt; 5</code>. Lower-confidence matches fall back to <code>unknown</code>.</p>
              <p class="report-dialog-meta"><a class="report-dialog-version-link" href="https://github.com/dreizehnutters/NmapView/releases" target="_blank" rel="noopener noreferrer">NmapView v3.4a</a><span class="report-dialog-meta-separator">·</span><a class="report-dialog-version-link" href="https://github.com/dreizehnutters/NmapView" target="_blank" rel="noopener noreferrer">Documentation &amp; Source</a></p>

              <section class="report-dialog-section" aria-labelledby="aboutDialogProjectTitle">
                <h3 id="aboutDialogProjectTitle" class="report-dialog-section-title">Project</h3>
                <div class="report-source-list">
                  <div class="report-source-item">
                    <div class="report-source-top">
                      <a class="report-source-name" href="https://github.com/dreizehnutters/NmapView" target="_blank" rel="noopener noreferrer">NmapView</a>
                      <span class="report-license-badge">MIT</span>
                    </div>
                    <p class="report-source-note">Project source, releases, and standalone XSL download.</p>
                  </div>
                </div>
              </section>

              <section class="report-dialog-section" aria-labelledby="aboutDialogSourcesTitle">
                <h3 id="aboutDialogSourcesTitle" class="report-dialog-section-title">Runtime Libraries</h3>
                <div class="report-source-list">
                  <div class="report-source-item">
                    <div class="report-source-top">
                      <a class="report-source-name" href="https://getbootstrap.com/" target="_blank" rel="noopener noreferrer">Bootstrap 5.3.8</a>
                      <span class="report-license-badge">MIT</span>
                    </div>
                    <p class="report-source-note">Base layout, spacing, and UI components.</p>
                  </div>
                  <div class="report-source-item">
                    <div class="report-source-top">
                      <a class="report-source-name" href="https://datatables.net/" target="_blank" rel="noopener noreferrer">DataTables 2.3.7 + Buttons, ColVis, FixedHeader</a>
                      <span class="report-license-badge">MIT</span>
                    </div>
                    <p class="report-source-note">Searchable tables, column toggles, and export controls.</p>
                  </div>
                  <div class="report-source-item">
                    <div class="report-source-top">
                      <a class="report-source-name" href="https://jquery.com/" target="_blank" rel="noopener noreferrer">jQuery 3.7.0</a>
                      <span class="report-license-badge">MIT</span>
                    </div>
                    <p class="report-source-note">Loaded as a DataTables runtime dependency.</p>
                  </div>
                  <div class="report-source-item">
                    <div class="report-source-top">
                      <a class="report-source-name" href="https://stuk.github.io/jszip/" target="_blank" rel="noopener noreferrer">JSZip 3.10.1</a>
                      <span class="report-license-badge">MIT or GPL-3.0+</span>
                    </div>
                    <p class="report-source-note">Loaded via the DataTables bundle for client-side export support.</p>
                  </div>
                  <div class="report-source-item">
                    <div class="report-source-top">
                      <a class="report-source-name" href="https://plotly.com/javascript/" target="_blank" rel="noopener noreferrer">Plotly.js 3.3.0</a>
                      <span class="report-license-badge">MIT</span>
                    </div>
                    <p class="report-source-note">Interactive charts and PNG plot export.</p>
                  </div>
                </div>
              </section>
            </div>
          </div>
        </dialog>
  </xsl:template>
  <xsl:template name="render-summary">
          <xsl:variable name="recorded-hosts" select="count(/nmaprun/host)"/>
          <xsl:variable name="runstats-total-hosts" select="number(/nmaprun/runstats/hosts/@total)"/>
          <xsl:variable name="total-hosts">
            <xsl:choose>
              <xsl:when test="$recorded-hosts &gt; 0">
                <xsl:value-of select="$recorded-hosts"/>
              </xsl:when>
              <xsl:otherwise>
                <xsl:value-of select="$runstats-total-hosts"/>
              </xsl:otherwise>
            </xsl:choose>
          </xsl:variable>
          <xsl:variable name="up-hosts">
            <xsl:choose>
              <xsl:when test="$recorded-hosts &gt; 0">
                <xsl:value-of select="count(/nmaprun/host[status/@state='up'])"/>
              </xsl:when>
              <xsl:otherwise>0</xsl:otherwise>
            </xsl:choose>
          </xsl:variable>
          <xsl:variable name="down-hosts">
            <xsl:choose>
              <xsl:when test="$recorded-hosts &gt; 0">
                <xsl:value-of select="count(/nmaprun/host[status/@state='down'])"/>
              </xsl:when>
              <xsl:otherwise>
                <xsl:value-of select="$runstats-total-hosts"/>
              </xsl:otherwise>
            </xsl:choose>
          </xsl:variable>
          <xsl:variable name="open-ports" select="count(/nmaprun/host/ports/port[state/@state='open'])"/>
          <xsl:variable name="unique-services" select="count(//host/ports/port[state/@state='open' and service/@name]
            [generate-id() = generate-id(
              key('serviceGroup',
                concat(
                  substring('ssl/', 1, (service/@tunnel = 'ssl') * string-length('ssl/')),
                  service/@name,
                  '-',
                  @protocol
                )
              )[1]
            )])"/>
          <xsl:variable name="rare-services" select="count(//host/ports/port[state/@state='open' and service/@name]
            [count(key('openPortProtocolGroup', concat(@portid, '-', @protocol))) = 1]
            [generate-id() = generate-id(
              key('rareServiceGroup',
                concat(
                  substring('ssl/', 1, count(script[@id='ssl-cert']) * string-length('ssl/')),
                  substring(service/@name, 1, string-length(service/@name) * (number(service/@conf) &gt; 5)),
                  substring('unknown', 1, string-length('unknown') * not(number(service/@conf) &gt; 5)),
                  '-',
                  @protocol
                )
              )[1]
            )])"/>
          <xsl:variable name="http-buckets" select="count(//host/ports/port[state/@state='open' and service/@name and (contains(translate(service/@name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'http') or script[@id='http-title'] or script[@id='http-headers'] or script[@id='http-server-header'])]
            [generate-id() = generate-id(
              key('httpServiceBucketGroup',
                concat(
                  substring('ssl/', 1, count(script[@id='ssl-cert']) * string-length('ssl/')),
                  substring(service/@name, 1, string-length(service/@name) * (number(service/@conf) &gt; 5)),
                  substring('unknown', 1, string-length('unknown') * not(number(service/@conf) &gt; 5)),
                  '|',
                  normalize-space(service/@product),
                  '|',
                  substring(normalize-space(service/@version), 1, string-length(normalize-space(service/@version)) * boolean(string(normalize-space(service/@product))))
                )
              )[1]
            )])"/>
          <xsl:variable name="duration-seconds" select="number(/nmaprun/runstats/finished/@time) - number(/nmaprun/@start)"/>
          <xsl:variable name="duration-hours" select="floor($duration-seconds div 3600)"/>
          <xsl:variable name="duration-minutes" select="floor(($duration-seconds mod 3600) div 60)"/>
          <xsl:variable name="duration-remainder-seconds" select="floor($duration-seconds mod 60)"/>
          <div id="summary" class="bg-light p-4 rounded shadow-sm">
            <div class="row g-3 mb-4">
              <div class="col-6 col-lg">
                <a class="summary-card-link" href="#openservices">
                  <div class="summary-card is-clickable">
                    <div class="summary-card-label">Open ports</div>
                    <div class="summary-card-value" id="summaryOpenPortsValue">
                      <xsl:value-of select="$open-ports"/>
                    </div>
                  </div>
                </a>
              </div>
              <div class="col-6 col-lg">
                <a class="summary-card-link" href="#serviceinventory">
                  <div class="summary-card is-clickable">
                    <div class="summary-card-label">Unique services</div>
                    <div class="summary-card-value" id="summaryUniqueServicesValue">
                      <xsl:value-of select="$unique-services"/>
                    </div>
                  </div>
                </a>
              </div>
              <div class="col-6 col-lg">
                <a class="summary-card-link" href="#serviceChart">
                  <div class="summary-card is-clickable">
                    <div class="summary-card-label">Rare services</div>
                    <div class="summary-card-value" id="summaryRareServicesValue">
                      <xsl:value-of select="$rare-services"/>
                    </div>
                  </div>
                </a>
              </div>
              <div class="col-6 col-lg">
                <div class="summary-card" title="Shannon entropy of the in-scope subnet's service distribution across up hosts. Higher values indicate a more heterogeneous service mix.">
                  <div class="summary-card-label">Subnet Entropy</div>
                  <div class="summary-card-value" id="summaryServiceEntropyValue">Calculating...</div>
                </div>
              </div>
            </div>
            <div class="progress summary-progress">
              <div class="progress-bar bg-success" id="summaryUpHostsBar" role="progressbar" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100" style="width: 0%;">
                <xsl:attribute name="style">
                  <xsl:text>width:</xsl:text>
                  <xsl:choose>
                    <xsl:when test="$total-hosts &gt; 0">
                      <xsl:value-of select="$up-hosts div $total-hosts * 100"/>
                    </xsl:when>
                    <xsl:otherwise>0</xsl:otherwise>
                  </xsl:choose>
                  <xsl:text>%;</xsl:text>
                </xsl:attribute>
                <xsl:value-of select="$up-hosts"/> Hosts up
              </div>
              <xsl:if test="number($down-hosts) &gt; 0">
                <div class="progress-bar bg-warning" id="summaryDownHostsBar" role="progressbar" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100" style="width: 0%;">
                  <xsl:attribute name="style">
                    <xsl:text>width:</xsl:text>
                    <xsl:choose>
                      <xsl:when test="$total-hosts &gt; 0">
                        <xsl:value-of select="$down-hosts div $total-hosts * 100"/>
                      </xsl:when>
                      <xsl:otherwise>0</xsl:otherwise>
                    </xsl:choose>
                    <xsl:text>%;</xsl:text>
                  </xsl:attribute>
                  <xsl:value-of select="$down-hosts"/> Hosts down
                </div>
              </xsl:if>
            </div>
            <details class="summary-command">
              <summary>Nmap Version: <xsl:value-of select="/nmaprun/@version"/><xsl:text> | </xsl:text>Scan Duration: <xsl:value-of select="/nmaprun/@startstr"/> - <xsl:value-of select="/nmaprun/runstats/finished/@timestr"/><xsl:text> (</xsl:text><xsl:if test="$duration-hours &gt; 0"><xsl:value-of select="$duration-hours"/><xsl:text>h </xsl:text></xsl:if><xsl:if test="$duration-minutes &gt; 0 or $duration-hours &gt; 0"><xsl:value-of select="$duration-minutes"/><xsl:text>m </xsl:text></xsl:if><xsl:value-of select="$duration-remainder-seconds"/><xsl:text>s)</xsl:text></summary>
              <pre>
                <xsl:attribute name="text">
                  <xsl:value-of select="/nmaprun/@args"/>
                </xsl:attribute>
                <xsl:value-of select="/nmaprun/@args"/>
              </pre>
            </details>
            <p class="summary-note"><span class="summary-note-icon">ⓘ</span>Nmap's service detection is heuristic and may include false positives.</p>
            <div class="summary-toolbar">
              <div class="density-controls" aria-label="Table density controls">
                <span class="density-controls-label">Table Density</span>
                <div class="btn-group btn-group-sm density-toggle-group" role="group" aria-label="Select table density">
                  <button type="button" class="btn btn-outline-secondary" id="densityComfortable" data-density="comfortable" aria-pressed="true">Comfortable</button>
                  <button type="button" class="btn btn-outline-secondary" id="densityDense" data-density="dense" aria-pressed="false">Dense</button>
                </div>
              </div>
            </div>
            <div class="keyword-highlight-controls" aria-label="Keyword highlighter">
              <input
                type="text"
                id="keywordHighlightInput"
                class="form-control"
                placeholder="sha1, ^ftp, ssh$, http*"
                aria-label="Comma-separated keywords or regex patterns to highlight"
              />
              <button type="button" class="btn btn-warning" id="highlightKeywordsButton">Globally Highlight Keywords</button>
              <button type="button" class="btn btn-outline-secondary" id="resetHighlightsButton">Reset</button>
            </div>
          </div>
  </xsl:template>
  <xsl:template name="render-footer">
        <hr class="my-3 footer-spacer"/>
        <footer class="footer bg-light py-3">
          <div class="container">
            <p class="text-muted mb-0 text-center">
              Generated with <a href="https://github.com/dreizehnutters/NmapView">NmapView</a></p>
          </div>
        </footer>
  </xsl:template>
  <xsl:template name="render-scripts">
        <script><![CDATA[
function appendText(parent, text) {
  parent.appendChild(document.createTextNode(text));
}

function initializeAboutDialog() {
  const trigger = document.getElementById("aboutDialogTrigger");
  const dialog = document.getElementById("aboutDialog");
  if (!trigger || !dialog) {
    return;
  }

  let returnFocusTarget = trigger;

  function openDialog() {
    returnFocusTarget = document.activeElement instanceof HTMLElement ? document.activeElement : trigger;
    if (typeof dialog.showModal === "function") {
      dialog.showModal();
    } else {
      dialog.setAttribute("open", "open");
    }
  }

  function closeDialog() {
    if (typeof dialog.close === "function") {
      dialog.close();
    } else {
      dialog.removeAttribute("open");
    }

    if (returnFocusTarget && typeof returnFocusTarget.focus === "function") {
      returnFocusTarget.focus();
    }
  }

  trigger.addEventListener("click", event => {
    event.preventDefault();
    openDialog();
  });

  dialog.querySelectorAll("[data-dialog-close='aboutDialog']").forEach(button => {
    button.addEventListener("click", closeDialog);
  });

  dialog.addEventListener("click", event => {
    if (event.target !== dialog) {
      return;
    }

    const rect = dialog.getBoundingClientRect();
    const insideDialog = rect.top <= event.clientY &&
      event.clientY <= rect.bottom &&
      rect.left <= event.clientX &&
      event.clientX <= rect.right;

    if (!insideDialog) {
      closeDialog();
    }
  });

  dialog.addEventListener("close", () => {
    if (returnFocusTarget && typeof returnFocusTarget.focus === "function") {
      returnFocusTarget.focus();
    }
  });
}

async function copyTextToClipboard(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }

  const input = document.createElement("textarea");
  input.value = text;
  input.setAttribute("readonly", "");
  input.style.position = "absolute";
  input.style.left = "-9999px";
  document.body.appendChild(input);
  input.select();
  document.execCommand("copy");
  document.body.removeChild(input);
}

let clipboardFeedbackTimer = null;

function showClipboardFeedback(message, isError = false) {
  if (!message) {
    return;
  }

  let feedback = document.getElementById("clipboardFeedback");
  if (!feedback) {
    feedback = document.createElement("div");
    feedback.id = "clipboardFeedback";
    feedback.className = "clipboard-feedback";
    feedback.setAttribute("aria-live", "polite");
    document.body.appendChild(feedback);
  }

  feedback.textContent = message;
  feedback.classList.toggle("is-error", isError);
  feedback.classList.add("is-visible");

  if (clipboardFeedbackTimer) {
    window.clearTimeout(clipboardFeedbackTimer);
  }

  clipboardFeedbackTimer = window.setTimeout(() => {
    feedback.classList.remove("is-visible");
  }, 1400);
}

async function copyTextWithFeedback(text, successMessage, emptyMessage = "Nothing to copy") {
  const normalizedText = String(text || "");
  if (!normalizedText.trim()) {
    showClipboardFeedback(emptyMessage, true);
    return false;
  }

  try {
    await copyTextToClipboard(normalizedText);
    showClipboardFeedback(successMessage || "Copied");
    return true;
  } catch (error) {
    showClipboardFeedback("Copy failed", true);
    return false;
  }
}

function getHostScopeState() {
  if (!window.nmapViewHostScopeState) {
    window.nmapViewHostScopeState = {
      allHosts: new Set(),
      selectedHosts: new Set(),
      pendingSelectedHosts: new Set(),
      dirty: false,
      redrawInProgress: false,
      dataTableFilterRegistered: false
    };
  }

  return window.nmapViewHostScopeState;
}

function normalizeHostAddress(address) {
  return String(address || "").trim();
}

function isHostInScope(address) {
  const normalizedAddress = normalizeHostAddress(address);
  if (!normalizedAddress) {
    return false;
  }

  const state = getHostScopeState();
  if (state.allHosts.size === 0) {
    return true;
  }

  return state.selectedHosts.has(normalizedAddress);
}

function getDataTableExportColumnSelector() {
  return ":visible:not(.not-export)";
}

function isRowIncludedInCurrentExportScope(row) {
  if (!row) {
    return true;
  }

  const address = normalizeHostAddress(row.dataset ? row.dataset.address : "");
  if (!address) {
    return true;
  }

  return isHostInScope(address);
}

function getDataTableExportRowSelector() {
  return function (_rowIndex, _rowData, rowNode) {
    return isRowIncludedInCurrentExportScope(rowNode);
  };
}

function getTableRows(tableId, options = {}) {
  const {
    searchApplied = false,
    requireAddress = false
  } = options;
  const table = document.getElementById(tableId);
  if (!table) {
    return [];
  }

  let rows = [];
  if (window.jQuery && $.fn.dataTable && $.fn.dataTable.isDataTable(table)) {
    const tableApi = $(table).DataTable();
    if (tableApi) {
      rows = tableApi.rows(searchApplied ? { search: "applied" } : undefined).nodes().toArray();
    }
  }

  if (rows.length === 0) {
    rows = Array.from(table.querySelectorAll("tbody tr"));
  }

  if (requireAddress) {
    rows = rows.filter(row => normalizeHostAddress(row.dataset.address));
  }

  return rows;
}

function initializeCpeCopy() {
  document.querySelectorAll(".cpe-copy").forEach(element => {
    element.addEventListener("click", async () => {
      const cpe = element.getAttribute("data-cpe");
      if (!cpe) return;

      try {
        await copyTextToClipboard(cpe);
        const previousTitle = element.getAttribute("title") || "";
        element.setAttribute("title", "Copied");
        element.classList.add("copied");
        window.setTimeout(() => {
          element.setAttribute("title", previousTitle || "Click to copy CPE");
          element.classList.remove("copied");
        }, 1200);
      } catch (error) {
        element.setAttribute("title", "Copy failed");
        window.setTimeout(() => {
          element.setAttribute("title", "Click to copy CPE");
        }, 1200);
      }
    });
  });
}

function parseCertificateExpiry(rawValue) {
  const trimmed = (rawValue || "").trim();
  const match = trimmed.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/);
  if (!match) {
    return null;
  }

  const [, year, month, day, hour, minute, second = "00"] = match;
  const timestamp = Date.UTC(
    Number(year),
    Number(month) - 1,
    Number(day),
    Number(hour),
    Number(minute),
    Number(second)
  );
  return Number.isNaN(timestamp) ? null : timestamp;
}

function formatCertificateDayCount(days) {
  if (days === 0) {
    return "today";
  }

  const absoluteDays = Math.abs(days);
  const dayLabel = absoluteDays === 1 ? "day" : "days";
  return days > 0 ? `in ${absoluteDays} ${dayLabel}` : `${absoluteDays} ${dayLabel} ago`;
}

function formatCertificateLifetimeYears(years) {
  const roundedYears = years >= 10 ? Math.round(years * 10) / 10 : Math.round(years * 100) / 100;
  return `${roundedYears} year${roundedYears === 1 ? "" : "s"}`;
}

function buildCertificateExpiryBadge(rawValidFrom, rawExpiry) {
  const dayMs = 24 * 60 * 60 * 1000;
  const msPerYear = 365.2425 * dayMs;
  const normalizedExpiry = String(rawExpiry || "").trim();
  const expiryTimestamp = parseCertificateExpiry(normalizedExpiry);
  if (expiryTimestamp === null) {
    return null;
  }

  const normalizedValidFrom = String(rawValidFrom || "").trim();
  const validFromTimestamp = parseCertificateExpiry(normalizedValidFrom);
  const now = Date.now();
  const daysRemaining = Math.ceil((expiryTimestamp - now) / dayMs);
  const validityYears = validFromTimestamp !== null
    ? (expiryTimestamp - validFromTimestamp) / msPerYear
    : null;
  const isLongLived = validityYears !== null && validityYears >= 10;
  let statusText = "Valid";
  let statusClass = "is-valid";

  if (expiryTimestamp < now) {
    statusText = "Expired";
    statusClass = "is-expired";
  } else if (daysRemaining <= 30) {
    statusText = "Expiring soon";
    statusClass = "is-expiring";
  } else if (isLongLived) {
    statusText = "10y+ lifetime";
    statusClass = "is-long-lived";
  }

  const badge = document.createElement("span");
  badge.className = `certificate-expiry-badge ${statusClass}`;
  badge.textContent = statusText;
  badge.title = isLongLived
    ? `${normalizedValidFrom} to ${normalizedExpiry} (${formatCertificateLifetimeYears(validityYears)})`
    : `${normalizedExpiry} (${formatCertificateDayCount(daysRemaining)})`;
  return badge;
}

function initializeCertificateExpiryAlerts() {
  document.querySelectorAll(".certificate-expiry-value").forEach(element => {
    if (element.querySelector(".certificate-expiry-badge")) {
      return;
    }

    const rawExpiry = (element.textContent || "").trim();
    const rawValidFrom = (element.getAttribute("data-valid-from") || "").trim();
    const badge = buildCertificateExpiryBadge(rawValidFrom, rawExpiry);
    if (badge) {
      element.appendChild(badge);
    }
  });
}

function formatVulnersChunks() {
  document.querySelectorAll(".vulners-chunks").forEach(container => {
    const raw = container.getAttribute("data-raw") || "";
    if (!raw.trim()) {
      return;
    }

    const cleaned = raw.replace(/\r\n/g, "\n").trim();
    const lines = cleaned
      .split("\n")
      .map(line => line.trim())
      .filter(Boolean);
    const entries = [];

    lines.forEach(line => {
      if (!line.includes("\t")) {
        return;
      }

      const parts = line.split("\t").map(part => part.trim()).filter(Boolean);
      if (parts.length < 3) {
        return;
      }

      const [id, score, url] = parts;
      if (!id || !score || !url) {
        return;
      }

      const urlMatch = url.match(/^https:\/\/vulners\.com\/([^/]+)\/(.+)$/);
      if (!urlMatch) {
        return;
      }

      entries.push({
        id,
        score: Number(score),
        scoreText: score,
        href: url
      });
    });

    container.textContent = "";
    if (entries.length > 0) {
      entries.sort((a, b) => b.score - a.score || a.id.localeCompare(b.id, undefined, {
        numeric: true,
        sensitivity: "base"
      }));
      const visibleEntries = entries.slice(0, 5);

      const details = document.createElement("details");
      const summary = document.createElement("summary");
      const list = document.createElement("div");

      details.className = "vulners-details";
      summary.className = "vulners-summary";
      list.className = "vulners-list";

      const findingLabel = entries.length === 1 ? "finding" : "findings";
      summary.textContent = `${entries.length} ${findingLabel}, top CVSS ${entries[0].scoreText}`;

      visibleEntries.forEach(entry => {
        const wrapper = document.createElement("div");
        const label = document.createElement("strong");
        const link = document.createElement("a");

        wrapper.style.marginBottom = "0.5em";
        label.textContent = `CVSS: ${entry.scoreText}`;
        link.href = entry.href;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.textContent = entry.id;

        wrapper.appendChild(label);
        appendText(wrapper, " - ");
        wrapper.appendChild(link);
        list.appendChild(wrapper);
      });

      if (entries.length > visibleEntries.length) {
        const more = document.createElement("div");
        more.style.color = "#6c757d";
        more.textContent = `Showing top ${visibleEntries.length} of ${entries.length} findings`;
        list.appendChild(more);
      }

      details.appendChild(summary);
      details.appendChild(list);
      container.appendChild(details);
      return;
    }

    const emptyState = document.createElement("em");
    emptyState.style.color = "#999";
    emptyState.textContent = "No valid Vulners links found";
    container.appendChild(emptyState);
  });
}

function initializeOpenServiceDetails() {
  document.querySelectorAll("#table-services tbody tr").forEach(row => {
    const detailsCell = row.querySelector(".open-service-details-cell");
    const source = row.querySelector(".open-service-detail-source");
    if (!detailsCell) {
      return;
    }

    detailsCell.textContent = "";
    if (!source) {
      detailsCell.dataset.order = "0";
      detailsCell.dataset.search = "";
      return;
    }

    const address = (source.getAttribute("data-address") || row.dataset.address || "").trim();
    const port = (source.getAttribute("data-port") || row.dataset.portid || "").trim();
    const protocol = (source.getAttribute("data-protocol") || row.dataset.protocol || "").trim();
    const fallbackPortLabel = port && protocol ? `${port}/${protocol}` : "";
    const httpRecord = {
      title: (source.getAttribute("data-http-title") || "").trim(),
      location: (source.getAttribute("data-http-location") || "").trim(),
      server: (source.getAttribute("data-http-server") || "").trim(),
      stack: (source.getAttribute("data-http-stack") || "").trim(),
      poweredBy: (source.getAttribute("data-http-powered-by") || "").trim()
    };
    const hasHttpDetails = Object.values(httpRecord).some(Boolean);
    const vulnersEntries = parseVulnersEntries(source.getAttribute("data-vulners") || "");
    const scriptRecords = Array.from(source.querySelectorAll(".open-service-script"))
      .map(scriptEntry => {
        const scriptPort = (scriptEntry.getAttribute("data-port") || "").trim();
        const scriptProtocol = (scriptEntry.getAttribute("data-protocol") || "").trim();
        return {
          id: (scriptEntry.getAttribute("data-id") || "").trim(),
          output: (scriptEntry.textContent || "").trim(),
          portLabel: scriptPort && scriptProtocol ? `${scriptPort}/${scriptProtocol}` : fallbackPortLabel,
          validFrom: (scriptEntry.getAttribute("data-valid-from") || "").trim(),
          validTo: (scriptEntry.getAttribute("data-valid-to") || "").trim(),
          selfSigned: (scriptEntry.getAttribute("data-self-signed") || "").trim() === "true"
        };
      })
      .filter(scriptRecord => scriptRecord.id && scriptRecord.output)
      .filter(scriptRecord => scriptRecord.id !== "vulners" && !shouldSuppressRawHttpScript(scriptRecord.id, hasHttpDetails))
      .sort(compareInventoryScriptRecords);

    if (!hasHttpDetails && vulnersEntries.length === 0 && scriptRecords.length === 0) {
      detailsCell.dataset.order = "0";
      detailsCell.dataset.search = "";
      return;
    }

    const detailsGroup = document.createElement("details");
    const detailsSummary = document.createElement("summary");
    const detailsBody = document.createElement("div");
    const hiddenScriptCount = scriptRecords.length;
    const hiddenDetailCount = (hasHttpDetails ? 1 : 0) + (vulnersEntries.length > 0 ? 1 : 0) + hiddenScriptCount;
    const searchTerms = [];

    detailsGroup.className = "service-inventory-script-group-details";
    detailsSummary.className = "service-inventory-script-group-summary";
    detailsBody.className = "service-inventory-script-group-body";
    detailsSummary.textContent = hiddenScriptCount > 0
      ? `Show Details (${hiddenScriptCount} script${hiddenScriptCount === 1 ? "" : "s"})`
      : `Show Details (${hiddenDetailCount})`;

    if (hasHttpDetails) {
      const httpBlock = document.createElement("div");
      httpBlock.className = "http-details-block service-inventory-http-block";

      if (fallbackPortLabel) {
        const httpPortLabel = document.createElement("div");
        httpPortLabel.className = "service-inventory-http-port-label";
        httpPortLabel.textContent = `HTTP (${fallbackPortLabel})`;
        httpBlock.appendChild(httpPortLabel);
      }

      appendServiceInventoryDetailRow(httpBlock, "Title", httpRecord.title);
      appendServiceInventoryDetailRow(httpBlock, "Server", httpRecord.server);
      appendServiceInventoryDetailRow(httpBlock, "Location", httpRecord.location);
      appendServiceInventoryDetailRow(httpBlock, "Stack", httpRecord.stack);
      appendServiceInventoryDetailRow(httpBlock, "Powered-By", httpRecord.poweredBy);
      detailsBody.appendChild(httpBlock);
      searchTerms.push(httpRecord.title, httpRecord.server, httpRecord.location, httpRecord.stack, httpRecord.poweredBy);
    }

    if (vulnersEntries.length > 0) {
      const vulnersContainer = document.createElement("div");
      const vulnersSummary = document.createElement("div");
      const vulnersList = document.createElement("div");
      const topFinding = vulnersEntries[0];

      vulnersContainer.className = "service-inventory-vulners";
      vulnersSummary.className = "service-inventory-vulners-summary";
      vulnersList.className = "service-inventory-vulners-list";
      vulnersSummary.textContent = topFinding
        ? `Vulners: ${vulnersEntries.length} finding${vulnersEntries.length === 1 ? "" : "s"}, top CVSS ${topFinding.scoreText}`
        : `Vulners: ${vulnersEntries.length} finding${vulnersEntries.length === 1 ? "" : "s"}`;

      vulnersEntries.slice(0, 3).forEach(entry => {
        const item = document.createElement("div");
        const score = document.createElement("strong");
        const link = document.createElement("a");

        item.className = "service-inventory-vulners-item";
        score.textContent = `CVSS ${entry.scoreText}`;
        link.href = entry.href;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.textContent = fallbackPortLabel ? `${entry.id} (${fallbackPortLabel})` : entry.id;
        item.appendChild(score);
        item.appendChild(link);
        vulnersList.appendChild(item);
      });

      if (vulnersEntries.length > 3) {
        const more = document.createElement("div");
        more.className = "service-inventory-vulners-more";
        more.textContent = `Showing a compact subset of ${vulnersEntries.length} findings`;
        vulnersList.appendChild(more);
      }

      vulnersContainer.appendChild(vulnersSummary);
      vulnersContainer.appendChild(vulnersList);
      detailsBody.appendChild(vulnersContainer);
      searchTerms.push(...vulnersEntries.map(entry => entry.id), ...vulnersEntries.map(entry => entry.scoreText));
    }

    if (scriptRecords.length > 0) {
      const scriptList = document.createElement("div");
      scriptList.className = "service-inventory-script-list service-inventory-script-group-body";

      scriptRecords.forEach(scriptRecord => {
        const scriptItem = document.createElement("details");
        const scriptLabel = document.createElement("summary");
        const scriptOutput = document.createElement("pre");

        scriptItem.className = "service-inventory-script-item-details";
        scriptLabel.className = "service-inventory-script-item-summary";
        scriptOutput.className = "service-inventory-script-output";
        scriptLabel.textContent = scriptRecord.portLabel
          ? `${scriptRecord.id} (${address} | ${scriptRecord.portLabel})`
          : `${scriptRecord.id} (${address})`;
        if (scriptRecord.id === "ssl-cert" && scriptRecord.validTo) {
          const expiryBadge = buildCertificateExpiryBadge(scriptRecord.validFrom, scriptRecord.validTo);
          if (expiryBadge) {
            scriptLabel.appendChild(expiryBadge);
          }
        }
        if (scriptRecord.id === "ssl-cert" && scriptRecord.selfSigned) {
          const selfSignedBadge = document.createElement("span");
          selfSignedBadge.className = "certificate-expiry-badge is-self-signed";
          selfSignedBadge.textContent = "Self-signed";
          selfSignedBadge.title = "Certificate subject and issuer match";
          scriptLabel.appendChild(selfSignedBadge);
        }
        scriptOutput.textContent = formatServiceInventoryScriptOutput(scriptRecord);
        scriptItem.appendChild(scriptLabel);
        scriptItem.appendChild(scriptOutput);
        scriptList.appendChild(scriptItem);
        searchTerms.push(scriptRecord.id, scriptRecord.output);
      });

      detailsBody.appendChild(scriptList);
    }

    detailsGroup.appendChild(detailsSummary);
    detailsGroup.appendChild(detailsBody);
    detailsCell.appendChild(detailsGroup);
    detailsCell.dataset.order = String(hiddenDetailCount);
    detailsCell.dataset.search = searchTerms
      .map(normalizeServiceInventorySearchValue)
      .filter(Boolean)
      .join(" ");
  });
}

function buildServiceInventoryVariantLabel(product, version) {
  const normalizedProduct = (product || "").trim();
  const normalizedVersion = (version || "").trim();

  if (!normalizedProduct) {
    return "Unknown product/version";
  }

  if (!normalizedVersion) {
    return `${normalizedProduct} (version unknown)`;
  }

  return `${normalizedProduct} ${normalizedVersion}`;
}

function buildServiceInventoryProductGroup(product) {
  const normalizedProduct = (product || "").trim();
  return normalizedProduct || "Unknown product/version";
}

function buildServiceInventoryHostLabel(hostname, address) {
  const normalizedHostname = (hostname || "").trim();
  const normalizedAddress = (address || "").trim();
  return normalizedHostname ? `${normalizedHostname} - ${normalizedAddress}` : normalizedAddress;
}

function compareInventoryText(left, right) {
  return (left || "").localeCompare(right || "", undefined, {
    numeric: true,
    sensitivity: "base"
  });
}

function compareInventoryPortLabels(left, right) {
  const [leftPort, leftProtocol] = String(left || "").split("/");
  const [rightPort, rightProtocol] = String(right || "").split("/");
  return Number(leftPort) - Number(rightPort) || compareInventoryText(leftProtocol, rightProtocol);
}

function formatEndpointBrowserHost(address) {
  const normalizedAddress = String(address || "").trim();
  if (!normalizedAddress) {
    return "";
  }

  return normalizedAddress.includes(":") &&
    !normalizedAddress.startsWith("[") &&
    !normalizedAddress.endsWith("]")
    ? `[${normalizedAddress}]`
    : normalizedAddress;
}

function inferEndpointBrowserScheme(serviceName, protocol) {
  const normalizedService = String(serviceName || "").trim().toLowerCase();
  const normalizedProtocol = String(protocol || "").trim().toLowerCase();

  if (normalizedService.startsWith("ssl/") || normalizedService.includes("https")) {
    return "https";
  }

  return normalizedProtocol === "udp" ? "http" : "http";
}

function createBrowserEndpointLink(address, port, protocol, serviceName, text, className = "endpoint-link") {
  const normalizedAddress = String(address || "").trim();
  const normalizedPort = String(port || "").trim();
  const normalizedProtocol = String(protocol || "").trim().toLowerCase();
  const linkText = String(text || normalizedPort).trim();

  if (!normalizedAddress || !normalizedPort) {
    const fallback = document.createElement("span");
    fallback.textContent = linkText;
    return fallback;
  }

  const link = document.createElement("a");
  const browserHost = formatEndpointBrowserHost(normalizedAddress);
  const browserScheme = inferEndpointBrowserScheme(serviceName, normalizedProtocol);

  link.className = className;
  link.href = `${browserScheme}://${browserHost}:${normalizedPort}`;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  link.textContent = linkText;
  return link;
}

function formatInventoryPortList(portSet) {
  return Array.from(portSet || []).sort(compareInventoryPortLabels).join(", ");
}

function compareInventoryScriptRecords(left, right) {
  return compareInventoryPortLabels(left.portLabel, right.portLabel) ||
    compareInventoryText(left.id, right.id) ||
    compareInventoryText(left.output, right.output);
}

function compareInventoryHttpRecords(left, right) {
  return compareInventoryPortLabels(left.portLabel, right.portLabel);
}

function appendServiceInventoryDetailRow(container, label, value) {
  const normalizedValue = String(value || "").trim();
  if (!normalizedValue) {
    return;
  }

  const row = document.createElement("div");
  const rowLabel = document.createElement("span");
  const rowValue = document.createElement("span");

  row.className = "service-inventory-http-row";
  rowLabel.className = "service-inventory-http-label";
  rowValue.className = "service-inventory-http-value";
  rowLabel.textContent = `${label}:`;
  rowValue.textContent = normalizedValue;
  row.appendChild(rowLabel);
  row.appendChild(rowValue);
  container.appendChild(row);
}

function shouldSuppressRawHttpScript(scriptId, hasHttpDetails) {
  if (!hasHttpDetails) {
    return false;
  }

  return [
    "http-title",
    "http-server-header",
    "http-headers",
    "fingerprint-strings"
  ].includes(String(scriptId || "").trim());
}

function parseVulnersEntries(raw) {
  const cleaned = String(raw || "").replace(/\r\n/g, "\n").trim();
  if (!cleaned) {
    return [];
  }

  const entries = [];
  cleaned
    .split("\n")
    .map(line => line.trim())
    .filter(Boolean)
    .forEach(line => {
      if (!line.includes("\t")) {
        return;
      }

      const parts = line.split("\t").map(part => part.trim()).filter(Boolean);
      if (parts.length < 3) {
        return;
      }

      const [id, score, url] = parts;
      if (!id || !score || !url || !/^https:\/\/vulners\.com\/[^/]+\/.+$/.test(url)) {
        return;
      }

      entries.push({
        id,
        score: Number(score),
        scoreText: score,
        href: url
      });
    });

  return entries.sort((a, b) => b.score - a.score || compareInventoryText(a.id, b.id));
}

function formatServiceInventoryScriptOutput(scriptRecord) {
  const output = String(scriptRecord && scriptRecord.output ? scriptRecord.output : "").replace(/\r\n/g, "\n");
  if (String(scriptRecord && scriptRecord.id ? scriptRecord.id : "").trim() !== "ssh-hostkey") {
    return output;
  }

  return output
    .split("\n")
    .filter(line => !/^\s*(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-[^\s]+|sk-ssh-ed25519[^\s]*|sk-ecdsa-sha2-[^\s]+)\s+/i.test(line))
    .map(line => line.replace(/^\s+/, ""))
    .join("\n")
    .trim();
}

function formatInventoryHostCount(count) {
  return `${count} Host${count === 1 ? "" : "s"}`;
}

function formatInventoryVariantSummary(variants) {
  const knownVariantCount = variants.filter(variant => !variant.isUnknown).length;
  const hasUnknown = variants.some(variant => variant.isUnknown);

  if (knownVariantCount === 0) {
    return "Unknown";
  }

  return `${knownVariantCount} Variant${knownVariantCount === 1 ? "" : "s"}${hasUnknown ? " + Unknown" : ""}`;
}

let serviceInventoryExportRows = [];
const serviceInventoryExportColumns = [
  "Service",
  "Bucket",
  "Host Count",
  "Host",
  "Port(s)",
  "HTTP Title",
  "HTTP Server",
  "HTTP Location",
  "HTTP Stack",
  "HTTP Powered-By",
  "Vulners",
  "NSE Scripts"
];

function buildServiceInventoryVulnersSummary(vulnersRecords) {
  return vulnersRecords
    .flatMap(record => record.entries.map(entry => {
      const suffix = record.portLabel ? ` (${record.portLabel})` : "";
      return `${entry.id}${suffix} [CVSS ${entry.scoreText}]`;
    }))
    .join("; ");
}

function buildServiceInventoryScriptSummary(scriptRecords, hostDisplayLabel) {
  return scriptRecords.map(scriptRecord => {
    return scriptRecord.portLabel
      ? `${scriptRecord.id} (${hostDisplayLabel} | ${scriptRecord.portLabel})`
      : `${scriptRecord.id} (${hostDisplayLabel})`;
  }).join("; ");
}

function normalizeServiceInventorySearchValue(value) {
  return String(value || "")
    .replace(/https?:\/\//gi, "")
    .replace(/\s+/g, " ")
    .trim();
}

function buildDataTableJsonExportAction(exportName) {
  return function (e, dt) {
    const visibleColumns = dt.columns(getDataTableExportColumnSelector());
    const headerIndexes = visibleColumns.indexes().toArray();
    const headers = visibleColumns.header().toArray().map(h => $(h).text().trim());

    const data = dt.rows({ search: 'applied' }).nodes().toArray()
      .filter(row => isRowIncludedInCurrentExportScope(row))
      .map(row => {
        const obj = {};
        headerIndexes.forEach((columnIndex, i) => {
          const cell = $(row).find('th, td').get(columnIndex);
          obj[headers[i]] = cell ? $(cell).text().trim() : '';
        });
        return obj;
      });

    const json = JSON.stringify(data, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${exportName}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };
}

function getScopedDataTableRows(dt) {
  if (!dt) {
    return [];
  }

  return dt.rows({ search: 'applied' }).nodes().toArray()
    .filter(row => isRowIncludedInCurrentExportScope(row));
}

function buildVisibleDataTableClipboardText(dt) {
  if (!dt) {
    return { text: "", rowCount: 0 };
  }

  const normalizeCell = value => String(value || "").replace(/\r?\n/g, " ").trim();
  const visibleColumns = dt.columns(getDataTableExportColumnSelector());
  const headerIndexes = visibleColumns.indexes().toArray();
  const header = visibleColumns.header().toArray().map(cell => normalizeCell($(cell).text()));
  const body = getScopedDataTableRows(dt).map(row =>
    headerIndexes.map(columnIndex => {
      const cell = $(row).find('th, td').get(columnIndex);
      return normalizeCell(cell ? $(cell).text() : "");
    })
  );
  const lines = [];

  if (header.length > 0) {
    lines.push(header.join("\t"));
  }

  body.forEach(row => {
    lines.push((Array.isArray(row) ? row : []).map(normalizeCell).join("\t"));
  });

  return {
    text: lines.join("\n"),
    rowCount: body.length
  };
}

async function copyVisibleDataTableRows(dt, rowLabel = "row") {
  const { text, rowCount } = buildVisibleDataTableClipboardText(dt);
  await copyTextWithFeedback(
    text,
    `Copied ${rowCount} ${rowLabel}${rowCount === 1 ? "" : "s"}`,
    "Nothing to copy"
  );
}

function formatServiceInventoryRowsAsDelimited(rows, delimiter = "\t") {
  const lines = [
    serviceInventoryExportColumns.join(delimiter),
    ...rows.map(row => serviceInventoryExportColumns.map(column => {
      const value = String(row[column] || "").replace(/\r?\n/g, " ").trim();
      return delimiter === ";"
        ? `"${value.replace(/"/g, '""')}"`
        : value;
    }).join(delimiter))
  ];
  return lines.join("\n");
}

function sanitizeServiceInventoryFilename(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "") || "service";
}

function buildServiceVariantAnchorId(serviceName, variantLabel) {
  return `servicevariant-${sanitizeServiceInventoryFilename(serviceName)}-${sanitizeServiceInventoryFilename(variantLabel)}`;
}

function detachServiceInventoryNestedTables() {
  return Array.from(document.querySelectorAll(".service-inventory-host-table")).map(table => {
    const parent = table.parentNode;
    const nextSibling = table.nextSibling;
    if (parent) {
      parent.removeChild(table);
    }
    return { table, parent, nextSibling };
  });
}

function restoreServiceInventoryNestedTables(detachedTables) {
  (Array.isArray(detachedTables) ? detachedTables : []).forEach(entry => {
    if (!entry || !entry.parent || !entry.table) {
      return;
    }

    if (entry.nextSibling && entry.nextSibling.parentNode === entry.parent) {
      entry.parent.insertBefore(entry.table, entry.nextSibling);
    } else {
      entry.parent.appendChild(entry.table);
    }
  });
}

function refreshServiceInventoryNestedTableGrouping(tableElement) {
  if (!tableElement) {
    return;
  }

  const headers = Array.from(tableElement.querySelectorAll("thead th")).map(header => (header.textContent || "").trim());
  const hostCountColumnIndex = headers.indexOf("Host Count");
  const rows = Array.from(tableElement.querySelectorAll("tbody tr"));
  let previousProductGroup = "";
  let previousVariantLabel = "";
  let variantBandIndex = -1;

  rows.forEach((row, rowIndex) => {
    row.classList.remove(
      "service-inventory-product-separator",
      "service-inventory-variant-separator",
      "service-inventory-variant-band-even",
      "service-inventory-variant-band-odd"
    );

    const productGroup = (row.dataset.productGroup || "").trim();
    const variantLabel = (row.dataset.variantLabel || "").trim();
    const hostCountDisplay = (row.dataset.variantHostCountDisplay || "").trim();
    const cells = row.querySelectorAll("td");

    if (hostCountColumnIndex !== -1 && cells.length > hostCountColumnIndex) {
      cells[hostCountColumnIndex].textContent = "";
    }

    if (rowIndex === 0) {
      variantBandIndex = 0;
      if (hostCountColumnIndex !== -1 && cells.length > hostCountColumnIndex) {
        cells[hostCountColumnIndex].textContent = hostCountDisplay;
      }
      row.classList.add("service-inventory-variant-band-even");
      previousProductGroup = productGroup;
      previousVariantLabel = variantLabel;
      return;
    }

    if (productGroup !== previousProductGroup) {
      row.classList.add("service-inventory-product-separator");
    } else if (variantLabel !== previousVariantLabel) {
      row.classList.add("service-inventory-variant-separator");
    }

    if (variantLabel !== previousVariantLabel) {
      variantBandIndex += 1;
    }

    row.classList.add(variantBandIndex % 2 === 0
      ? "service-inventory-variant-band-even"
      : "service-inventory-variant-band-odd");

    if (variantLabel !== previousVariantLabel && hostCountColumnIndex !== -1 && cells.length > hostCountColumnIndex) {
      cells[hostCountColumnIndex].textContent = hostCountDisplay;
    }

    previousProductGroup = productGroup;
    previousVariantLabel = variantLabel;
  });
}

function initializeServiceInventoryNestedTable(tableElement) {
  if (!tableElement || !(window.jQuery && $.fn.dataTable)) {
    return;
  }

  if ($.fn.dataTable.isDataTable(tableElement)) {
    const existing = $(tableElement).DataTable();
    const existingWrapper = existing.table().container();
    if (existingWrapper) {
      existingWrapper.classList.add("service-inventory-host-table-wrapper");
    }
    existing.columns.adjust();
    refreshServiceInventoryNestedTableGrouping(tableElement);
    return existing;
  }

  const exportName = tableElement.getAttribute("data-export-name") || "nmapview-service-details";
  const api = $(tableElement).DataTable({
    paging: false,
    searching: true,
    info: true,
    ordering: true,
    order: [[0, 'asc'], [2, 'asc']],
    stateSave: false,
    autoWidth: false,
    dom: '<"d-flex justify-content-between align-items-center mb-2"fB>rti',
    buttons: [
      {
        extend: 'colvis',
        text: 'Columns',
        className: 'btn btn-light'
      },
      {
        extend: 'collection',
        text: 'Copy',
        className: 'btn btn-light',
        buttons: [
          {
            text: 'All',
            action: async function (e, dt) {
              await copyVisibleDataTableRows(dt);
            }
          },
          {
            text: 'IP:Ports',
            action: async function (e, dt) {
              const endpoints = [];

              dt.rows({ search: 'applied' }).nodes().toArray().forEach(row => {
                const address = (row.getAttribute('data-address') || '').trim();
                const rawPorts = (row.getAttribute('data-ports') || '').trim();
                if (!address || !rawPorts) {
                  return;
                }

                rawPorts
                  .split(',')
                  .map(port => port.trim())
                  .filter(Boolean)
                  .forEach(portLabel => {
                    const [port] = portLabel.split('/');
                    if (port) {
                      endpoints.push(`${address}:${port}`);
                    }
                  });
              });

              const uniqueEndpoints = [...new Set(endpoints)];
              await copyTextWithFeedback(
                uniqueEndpoints.join('\n'),
                `Copied ${uniqueEndpoints.length} IP:Port entr${uniqueEndpoints.length === 1 ? "y" : "ies"}`
              );
            }
          },
          {
            text: 'IPs',
            action: async function (e, dt) {
              const addresses = [];

              dt.rows({ search: 'applied' }).nodes().toArray().forEach(row => {
                const address = (row.getAttribute('data-address') || '').trim();
                if (address) {
                  addresses.push(address);
                }
              });

              const uniqueAddresses = [...new Set(addresses)]
                .sort((left, right) => left.localeCompare(right, undefined, {
                  numeric: true,
                  sensitivity: 'base'
                }));

              await copyTextWithFeedback(
                uniqueAddresses.join('\n'),
                `Copied ${uniqueAddresses.length} IP${uniqueAddresses.length === 1 ? "" : "s"}`
              );
            }
          },
          {
            text: 'Ports',
            action: async function (e, dt) {
              const ports = [];

              dt.rows({ search: 'applied' }).nodes().toArray().forEach(row => {
                const rawPorts = (row.getAttribute('data-ports') || '').trim();
                if (!rawPorts) {
                  return;
                }

                rawPorts
                  .split(',')
                  .map(port => port.trim())
                  .filter(Boolean)
                  .forEach(portLabel => {
                    const [port] = portLabel.split('/');
                    if (port) {
                      ports.push(port);
                    }
                  });
              });

              const uniquePorts = [...new Set(ports)]
                .sort((left, right) => Number(left) - Number(right) || left.localeCompare(right, undefined, {
                  numeric: true,
                  sensitivity: 'base'
                }));

              await copyTextWithFeedback(
                uniquePorts.join(','),
                `Copied ${uniquePorts.length} port${uniquePorts.length === 1 ? "" : "s"}`
              );
            }
          }
        ]
      },
      {
        extend: 'csvHtml5',
        text: 'CSV',
        filename: exportName,
        fieldSeparator: ';',
        exportOptions: { rows: getDataTableExportRowSelector(), columns: getDataTableExportColumnSelector(), orthogonal: 'export' },
        className: 'btn btn-light'
      },
      {
        extend: 'excelHtml5',
        text: 'Excel',
        filename: exportName,
        autoFilter: true,
        exportOptions: { rows: getDataTableExportRowSelector(), columns: getDataTableExportColumnSelector(), orthogonal: 'export' },
        className: 'btn btn-light'
      },
      {
        text: 'JSON',
        className: 'btn btn-light',
        action: buildDataTableJsonExportAction(exportName)
      }
    ]
  });
  api.on("draw.dt", function () {
    refreshServiceInventoryNestedTableGrouping(tableElement);
  });
  const wrapper = api.table().container();
  if (wrapper) {
    wrapper.classList.add("service-inventory-host-table-wrapper");
  }
  refreshServiceInventoryNestedTableGrouping(tableElement);
  return api;
}

function initializeServiceInventoryNestedTables() {
  document.querySelectorAll(".service-inventory-service-details").forEach(details => {
    const nestedTable = details.querySelector(".service-inventory-host-table");
    if (!nestedTable) {
      return;
    }

    const ensureInitialized = () => {
      const api = initializeServiceInventoryNestedTable(nestedTable);
      if (api && typeof api.columns?.adjust === "function") {
        api.columns.adjust();
      }
    };

    ensureInitialized();

    details.addEventListener("toggle", () => {
      if (details.open) {
        ensureInitialized();
      }
    });
  });
}

function buildServiceInventoryTable() {
  const tableBody = document.getElementById("serviceInventoryTableBody");
  const entries = Array.from(document.querySelectorAll("#serviceInventoryData .service-inventory-entry"));
  if (!tableBody || entries.length === 0) {
    return;
  }

  const services = new Map();

  entries.forEach(entry => {
    const service = (entry.getAttribute("data-service") || "").trim();
    const address = (entry.getAttribute("data-address") || "").trim();
    const hostname = (entry.getAttribute("data-hostname") || "").trim();
    const product = entry.getAttribute("data-product") || "";
    const version = entry.getAttribute("data-version") || "";
    const port = (entry.getAttribute("data-port") || "").trim();
    const protocol = (entry.getAttribute("data-protocol") || "").trim();
    const portLabel = port && protocol ? `${port}/${protocol}` : "";
    const variantLabel = buildServiceInventoryVariantLabel(product, version);
    const extraInfo = (entry.getAttribute("data-extra-info") || "").trim();

    if (!service || !address || !isHostInScope(address)) {
      return;
    }

    if (!services.has(service)) {
      services.set(service, {
        name: service,
        hosts: new Map(),
        ports: new Set(),
        variants: new Map()
      });
    }

    const serviceRecord = services.get(service);
    serviceRecord.hosts.set(address, { address, hostname });
    if (portLabel) {
      serviceRecord.ports.add(portLabel);
    }

    if (!serviceRecord.variants.has(variantLabel)) {
      serviceRecord.variants.set(variantLabel, {
        label: variantLabel,
        productGroup: buildServiceInventoryProductGroup(product),
        isUnknown: variantLabel === "Unknown product/version",
        hosts: new Map(),
        ports: new Set()
      });
    }

    const variantRecord = serviceRecord.variants.get(variantLabel);
    if (!variantRecord.hosts.has(address)) {
      variantRecord.hosts.set(address, {
        address,
        hostname,
        ports: new Set(),
        extraInfoRecords: new Map(),
        scripts: new Map(),
        httpDetails: new Map(),
        vulners: new Map()
      });
    }
    const variantHostRecord = variantRecord.hosts.get(address);
    if (!variantHostRecord.hostname && hostname) {
      variantHostRecord.hostname = hostname;
    }
    if (portLabel) {
      variantHostRecord.ports.add(portLabel);
      variantRecord.ports.add(portLabel);
    }
    if (extraInfo) {
      const extraInfoKey = portLabel || `${service}|${address}|extra-info`;
      if (!variantHostRecord.extraInfoRecords.has(extraInfoKey)) {
        variantHostRecord.extraInfoRecords.set(extraInfoKey, {
          portLabel: portLabel || "",
          value: extraInfo
        });
      }
    }

    const httpTitle = (entry.getAttribute("data-http-title") || "").trim();
    const httpLocation = (entry.getAttribute("data-http-location") || "").trim();
    const httpServer = (entry.getAttribute("data-http-server") || "").trim();
    const httpStack = (entry.getAttribute("data-http-stack") || "").trim();
    const httpPoweredBy = (entry.getAttribute("data-http-powered-by") || "").trim();
    const rawVulners = (entry.getAttribute("data-vulners") || "").trim();
    if ([httpTitle, httpLocation, httpServer, httpStack, httpPoweredBy].some(Boolean)) {
      const httpKey = portLabel || `${service}|${address}`;
      if (!variantHostRecord.httpDetails.has(httpKey)) {
        variantHostRecord.httpDetails.set(httpKey, {
          portLabel: portLabel || "",
          title: httpTitle,
          location: httpLocation,
          server: httpServer,
          stack: httpStack,
          poweredBy: httpPoweredBy
        });
      }
    }
    const vulnersEntries = parseVulnersEntries(rawVulners);
    if (vulnersEntries.length > 0) {
      const vulnersKey = portLabel || `${service}|${address}|vulners`;
      if (!variantHostRecord.vulners.has(vulnersKey)) {
        variantHostRecord.vulners.set(vulnersKey, {
          portLabel: portLabel || "",
          entries: vulnersEntries
        });
      }
    }

    Array.from(entry.querySelectorAll(".service-inventory-script")).forEach(scriptEntry => {
      const scriptId = (scriptEntry.getAttribute("data-id") || "").trim();
      const scriptOutput = (scriptEntry.textContent || "").trim();
      const scriptPort = (scriptEntry.getAttribute("data-port") || "").trim();
      const scriptProtocol = (scriptEntry.getAttribute("data-protocol") || "").trim();
      const scriptPortLabel = scriptPort && scriptProtocol ? `${scriptPort}/${scriptProtocol}` : portLabel;
      const scriptValidFrom = (scriptEntry.getAttribute("data-valid-from") || "").trim();
      const scriptValidTo = (scriptEntry.getAttribute("data-valid-to") || "").trim();
      const scriptSelfSigned = (scriptEntry.getAttribute("data-self-signed") || "").trim() === "true";

      if (!scriptId || !scriptOutput) {
        return;
      }

      const scriptKey = `${scriptPortLabel}::${scriptId}::${scriptOutput}`;
      if (!variantHostRecord.scripts.has(scriptKey)) {
        variantHostRecord.scripts.set(scriptKey, {
          id: scriptId,
          output: scriptOutput,
          portLabel: scriptPortLabel || "",
          validFrom: scriptValidFrom,
          validTo: scriptValidTo,
          selfSigned: scriptSelfSigned
        });
      }
    });
  });

  const sortedServices = Array.from(services.values()).sort((left, right) => {
    return right.hosts.size - left.hosts.size || compareInventoryText(left.name, right.name);
  });

  serviceInventoryExportRows = [];
  tableBody.textContent = "";
  let nestedTableIndex = 0;

  sortedServices.forEach(serviceRecord => {
    const row = document.createElement("tr");
    const hostsCell = document.createElement("td");
    const serviceDetails = document.createElement("details");
    const serviceSummary = document.createElement("summary");
    const serviceLine = document.createElement("div");
    const serviceTitle = document.createElement("span");
    const serviceMeta = document.createElement("span");
    const serviceBody = document.createElement("div");
    const hostTable = document.createElement("table");
    const hostTableHead = document.createElement("thead");
    const hostTableHeadRow = document.createElement("tr");
    const hostTableBucketHeader = document.createElement("th");
    const hostTableHostCountHeader = document.createElement("th");
    const hostTableHostHeader = document.createElement("th");
    const hostTablePortsHeader = document.createElement("th");
    const hostTableServiceHeader = document.createElement("th");
    const hostTableBody = document.createElement("tbody");
    const variants = Array.from(serviceRecord.variants.values()).sort((left, right) => {
      if (left.isUnknown !== right.isUnknown) {
        return left.isUnknown ? 1 : -1;
      }
      return compareInventoryText(left.productGroup, right.productGroup) || compareInventoryText(left.label, right.label);
    });
    const searchTerms = new Set();

    serviceDetails.className = "service-inventory-service-details";
    serviceSummary.className = "service-inventory-service-summary";
    serviceLine.className = "service-inventory-summary-line";
    serviceTitle.className = "service-inventory-service-title";
    serviceMeta.className = "service-inventory-service-meta";
    serviceBody.className = "service-inventory-service-body";
    hostTable.className = "service-inventory-host-table";
    hostTable.id = `serviceInventoryNestedTable${nestedTableIndex += 1}`;
    hostTable.setAttribute("data-export-name", `nmapview-service-${sanitizeServiceInventoryFilename(serviceRecord.name)}`);
    hostTableBucketHeader.className = "service-inventory-host-bucket-column";
    hostTableHostCountHeader.className = "service-inventory-host-count-column";
    hostTableHostHeader.className = "service-inventory-host-column";
    hostTablePortsHeader.className = "service-inventory-host-ports-column";
    hostTableServiceHeader.className = "service-inventory-host-service-column";

    hostsCell.className = "service-inventory-hosts-cell";
    hostsCell.dataset.order = String(serviceRecord.hosts.size);
    searchTerms.add(normalizeServiceInventorySearchValue(serviceRecord.name));

    serviceTitle.textContent = serviceRecord.name;
    serviceMeta.textContent = `${formatInventoryHostCount(serviceRecord.hosts.size)} • ${formatInventoryVariantSummary(variants)}`;
    serviceLine.appendChild(serviceTitle);
    serviceLine.appendChild(serviceMeta);
    serviceSummary.appendChild(serviceLine);
    hostTableBucketHeader.textContent = "Product";
    hostTableHostCountHeader.innerHTML = '<span title="Unique in-scope hosts in this product/version variant.">Host Count</span>';
    hostTableHostHeader.textContent = "Host";
    hostTablePortsHeader.textContent = "Port(s)";
    hostTableServiceHeader.textContent = "Details";
    hostTableHeadRow.appendChild(hostTableBucketHeader);
    hostTableHeadRow.appendChild(hostTableHostCountHeader);
    hostTableHeadRow.appendChild(hostTableHostHeader);
    hostTableHeadRow.appendChild(hostTablePortsHeader);
    hostTableHeadRow.appendChild(hostTableServiceHeader);
    hostTableHead.appendChild(hostTableHeadRow);

    const serviceScopedExportRows = [];

    variants.forEach(variantRecord => {
      searchTerms.add(normalizeServiceInventorySearchValue(variantRecord.label));
      searchTerms.add(normalizeServiceInventorySearchValue(variantRecord.productGroup));
      const variantAnchorId = buildServiceVariantAnchorId(serviceRecord.name, variantRecord.label);
      let variantAnchorAssigned = false;
      const variantHostCount = variantRecord.hosts.size;
      const hosts = Array.from(variantRecord.hosts.values()).sort((left, right) => {
        const leftLabel = buildServiceInventoryHostLabel(left.hostname, left.address);
        const rightLabel = buildServiceInventoryHostLabel(right.hostname, right.address);
        return compareInventoryText(leftLabel, rightLabel);
      });

      hosts.forEach(hostRecord => {
        const row = document.createElement("tr");
        const bucketCell = document.createElement("td");
        const hostCountCell = document.createElement("td");
        const bucketLabel = document.createElement("a");
        const hostCell = document.createElement("td");
        const portsCell = document.createElement("td");
        const serviceCell = document.createElement("td");
        const link = document.createElement("a");
        const portLabels = Array.from(hostRecord.ports || []).sort(compareInventoryPortLabels);
        const extraInfoRecords = Array.from(hostRecord.extraInfoRecords ? hostRecord.extraInfoRecords.values() : [])
          .sort((left, right) => compareInventoryPortLabels(left.portLabel, right.portLabel) || compareInventoryText(left.value, right.value));
        const httpDetails = Array.from(hostRecord.httpDetails ? hostRecord.httpDetails.values() : [])
          .sort(compareInventoryHttpRecords);
        const vulnersRecords = Array.from(hostRecord.vulners ? hostRecord.vulners.values() : [])
          .sort((left, right) => compareInventoryPortLabels(left.portLabel, right.portLabel));
        const scriptRecords = Array.from(hostRecord.scripts ? hostRecord.scripts.values() : [])
          .sort(compareInventoryScriptRecords);
        const hostDisplayLabel = buildServiceInventoryHostLabel(hostRecord.hostname, hostRecord.address);
        const filteredScriptRecords = scriptRecords.filter(scriptRecord =>
          scriptRecord.id !== "vulners" &&
          !shouldSuppressRawHttpScript(scriptRecord.id, httpDetails.length > 0)
        );
        const primaryHttpRecord = httpDetails[0] || {};
        const hostSearchTerms = [
          hostDisplayLabel,
          hostRecord.address,
          hostRecord.hostname,
          ...portLabels,
          ...extraInfoRecords.map(record => record.value),
          ...httpDetails.flatMap(record => [
            record.title,
            record.server,
            record.location,
            record.stack,
            record.poweredBy
          ]),
          ...filteredScriptRecords.map(record => record.id)
        ];

        row.setAttribute("data-address", hostRecord.address);
        row.setAttribute("data-ports", portLabels.join(","));
        row.dataset.productGroup = variantRecord.productGroup;
        row.dataset.variantLabel = variantRecord.label;
        row.dataset.variantHostCountDisplay = String(variantHostCount);
        hostSearchTerms
          .map(normalizeServiceInventorySearchValue)
          .filter(Boolean)
          .forEach(term => searchTerms.add(term));

        link.className = "service-inventory-host-link";
        link.href = `#onlinehosts-${hostRecord.address.replace(/[.:]/g, "-")}`;
        link.textContent = hostDisplayLabel;
        const isFirstRowForVariant = !variantAnchorAssigned;
        if (!variantAnchorAssigned) {
          row.id = variantAnchorId;
          variantAnchorAssigned = true;
        }
        bucketLabel.className = "service-inventory-bucket-label";
        bucketLabel.href = `#${variantAnchorId}`;
        bucketLabel.textContent = variantRecord.label;
        bucketCell.appendChild(bucketLabel);
        hostCountCell.dataset.order = String(variantHostCount);
        hostCountCell.dataset.search = String(variantHostCount);
        if (isFirstRowForVariant) {
          hostCountCell.textContent = String(variantHostCount);
        }
        hostCell.appendChild(link);
        if (portLabels.length > 0) {
          portLabels.forEach((portLabel, index) => {
            const [port, protocol] = String(portLabel || "").split("/");
            if (index > 0) {
              portsCell.appendChild(document.createTextNode(", "));
            }
            portsCell.appendChild(createBrowserEndpointLink(
              hostRecord.address,
              port,
              protocol || "",
              serviceRecord.name,
              portLabel
            ));
          });
        }
        if (extraInfoRecords.length > 0 || httpDetails.length > 0 || vulnersRecords.length > 0 || filteredScriptRecords.length > 0) {
          const detailsGroup = document.createElement("details");
          const detailsSummary = document.createElement("summary");
          const detailsBody = document.createElement("div");
          const hiddenScriptCount = filteredScriptRecords.length;
          const hiddenDetailCount = extraInfoRecords.length +
            httpDetails.length +
            vulnersRecords.length +
            hiddenScriptCount;

          detailsGroup.className = "service-inventory-script-group-details";
          detailsSummary.className = "service-inventory-script-group-summary";
          detailsBody.className = "service-inventory-script-group-body";
          detailsSummary.textContent = hiddenScriptCount > 0
            ? `Show Details (${hiddenScriptCount} script${hiddenScriptCount === 1 ? "" : "s"})`
            : `Show Details (${hiddenDetailCount})`;

          if (extraInfoRecords.length > 0) {
            const extraInfoContainer = document.createElement("div");
            extraInfoContainer.className = "service-inventory-extra-info-details";

            extraInfoRecords.forEach(extraInfoRecord => {
              const extraInfoBlock = document.createElement("div");
              extraInfoBlock.className = "service-inventory-extra-info-block";

              if (extraInfoRecord.portLabel) {
                const extraInfoPortLabel = document.createElement("div");
                extraInfoPortLabel.className = "service-inventory-extra-info-port-label";
                extraInfoPortLabel.textContent = `Extra Info (${extraInfoRecord.portLabel})`;
                extraInfoBlock.appendChild(extraInfoPortLabel);
              }

              const extraInfoValue = document.createElement("div");
              extraInfoValue.className = "service-inventory-extra-info-value";
              extraInfoValue.textContent = extraInfoRecord.value;
              extraInfoBlock.appendChild(extraInfoValue);
              extraInfoContainer.appendChild(extraInfoBlock);
            });

            detailsBody.appendChild(extraInfoContainer);
          }

          if (httpDetails.length > 0) {
            const httpDetailsContainer = document.createElement("div");
            httpDetailsContainer.className = "service-inventory-http-details";

            httpDetails.forEach(httpRecord => {
              const httpBlock = document.createElement("div");
              httpBlock.className = "http-details-block service-inventory-http-block";

              if (httpRecord.portLabel) {
                const httpPortLabel = document.createElement("div");
                httpPortLabel.className = "service-inventory-http-port-label";
                httpPortLabel.textContent = `HTTP (${httpRecord.portLabel})`;
                httpBlock.appendChild(httpPortLabel);
              }

              appendServiceInventoryDetailRow(httpBlock, "Title", httpRecord.title);
              appendServiceInventoryDetailRow(httpBlock, "Server", httpRecord.server);
              appendServiceInventoryDetailRow(httpBlock, "Location", httpRecord.location);
              appendServiceInventoryDetailRow(httpBlock, "Stack", httpRecord.stack);
              appendServiceInventoryDetailRow(httpBlock, "Powered-By", httpRecord.poweredBy);
              httpDetailsContainer.appendChild(httpBlock);
            });

            detailsBody.appendChild(httpDetailsContainer);
          }

          if (vulnersRecords.length > 0) {
            const vulnersContainer = document.createElement("div");
            const vulnersSummary = document.createElement("div");
            const vulnersList = document.createElement("div");
            const flattenedVulners = vulnersRecords.flatMap(record =>
              record.entries.map(entry => ({
                ...entry,
                portLabel: record.portLabel
              }))
            );
            const totalFindings = flattenedVulners.length;
            const topFinding = flattenedVulners[0];

            vulnersContainer.className = "service-inventory-vulners";
            vulnersSummary.className = "service-inventory-vulners-summary";
            vulnersList.className = "service-inventory-vulners-list";
            vulnersSummary.textContent = topFinding
              ? `Vulners: ${totalFindings} finding${totalFindings === 1 ? "" : "s"}, top CVSS ${topFinding.scoreText}`
              : `Vulners: ${totalFindings} finding${totalFindings === 1 ? "" : "s"}`;

            flattenedVulners.slice(0, 3).forEach(entry => {
              const item = document.createElement("div");
              const score = document.createElement("strong");
              const link = document.createElement("a");

              item.className = "service-inventory-vulners-item";
              score.textContent = `CVSS ${entry.scoreText}`;
              link.href = entry.href;
              link.target = "_blank";
              link.rel = "noopener noreferrer";
              link.textContent = entry.portLabel ? `${entry.id} (${entry.portLabel})` : entry.id;
              item.appendChild(score);
              item.appendChild(link);
              vulnersList.appendChild(item);
            });

            if (totalFindings > 3) {
              const more = document.createElement("div");
              more.className = "service-inventory-vulners-more";
              more.textContent = `Showing a compact subset of ${totalFindings} findings`;
              vulnersList.appendChild(more);
            }

            vulnersContainer.appendChild(vulnersSummary);
            vulnersContainer.appendChild(vulnersList);
            detailsBody.appendChild(vulnersContainer);
          }

          if (filteredScriptRecords.length > 0) {
            const scriptList = document.createElement("div");

            scriptList.className = "service-inventory-script-list";

            filteredScriptRecords.forEach(scriptRecord => {
            const scriptItem = document.createElement("details");
            const scriptLabel = document.createElement("summary");
            const scriptOutput = document.createElement("pre");

            scriptItem.className = "service-inventory-script-item-details";
            scriptLabel.className = "service-inventory-script-item-summary";
            scriptOutput.className = "service-inventory-script-output";
            scriptLabel.textContent = scriptRecord.portLabel
              ? `${scriptRecord.id} (${hostDisplayLabel} | ${scriptRecord.portLabel})`
              : `${scriptRecord.id} (${hostDisplayLabel})`;
            if (scriptRecord.id === "ssl-cert" && scriptRecord.validTo) {
              const expiryBadge = buildCertificateExpiryBadge(scriptRecord.validFrom, scriptRecord.validTo);
              if (expiryBadge) {
                scriptLabel.appendChild(expiryBadge);
              }
            }
            if (scriptRecord.id === "ssl-cert" && scriptRecord.selfSigned) {
              const selfSignedBadge = document.createElement("span");
              selfSignedBadge.className = "certificate-expiry-badge is-self-signed";
              selfSignedBadge.textContent = "Self-signed";
              selfSignedBadge.title = "Certificate subject and issuer match";
              scriptLabel.appendChild(selfSignedBadge);
            }
            scriptOutput.textContent = formatServiceInventoryScriptOutput(scriptRecord);
            scriptItem.appendChild(scriptLabel);
            scriptItem.appendChild(scriptOutput);
            scriptList.appendChild(scriptItem);
            });

            scriptList.classList.add("service-inventory-script-group-body");
            detailsBody.appendChild(scriptList);
          }

          detailsGroup.appendChild(detailsSummary);
          detailsGroup.appendChild(detailsBody);
          serviceCell.appendChild(detailsGroup);
        }

        const exportRow = {
          "Service": serviceRecord.name,
          "Bucket": variantRecord.label,
          "Host Count": String(variantHostCount),
          "Host": hostDisplayLabel,
          "Port(s)": formatInventoryPortList(hostRecord.ports),
          "HTTP Title": primaryHttpRecord.title || "",
          "HTTP Server": primaryHttpRecord.server || "",
          "HTTP Location": primaryHttpRecord.location || "",
          "HTTP Stack": primaryHttpRecord.stack || "",
          "HTTP Powered-By": primaryHttpRecord.poweredBy || "",
          "Vulners": buildServiceInventoryVulnersSummary(vulnersRecords),
          "NSE Scripts": buildServiceInventoryScriptSummary(filteredScriptRecords, hostDisplayLabel)
        };
        serviceInventoryExportRows.push(exportRow);
        serviceScopedExportRows.push(exportRow);
        row.appendChild(bucketCell);
        row.appendChild(hostCountCell);
        row.appendChild(hostCell);
        row.appendChild(portsCell);
        row.appendChild(serviceCell);
        hostTableBody.appendChild(row);
      });
    });

    hostTable.appendChild(hostTableHead);
    hostTable.appendChild(hostTableBody);
    serviceBody.appendChild(hostTable);
    serviceDetails.appendChild(serviceSummary);
    serviceDetails.appendChild(serviceBody);
    hostsCell.appendChild(serviceDetails);
    hostsCell.dataset.search = Array.from(searchTerms).join(" ");

    row.appendChild(hostsCell);
    tableBody.appendChild(row);
  });
}

function initializeNavbarToggle() {
  const menu = document.getElementById("navbarNav");
  if (!menu) return;
  menu.hidden = false;
  window.requestAnimationFrame(syncDataTableFixedHeaders);
}

function initializeSectionNav() {
  const navLinks = Array.from(document.querySelectorAll("#navbarNav .navbar-nav.me-auto .nav-link[href^='#']"));
  if (navLinks.length === 0) {
    return;
  }

  const sections = navLinks
    .map(link => {
      const hash = link.getAttribute("href");
      if (!hash) {
        return null;
      }

      const section = document.querySelector(hash);
      if (!section) {
        return null;
      }

      return { link, hash, section };
    })
    .filter(Boolean);

  if (sections.length === 0) {
    return;
  }

  function setActiveLink(hash) {
    let normalizedHash = hash;
    if (hash && hash.startsWith("#onlinehosts-")) {
      normalizedHash = "#onlinehosts";
    } else if (hash && hash.startsWith("#servicevariant-")) {
      normalizedHash = "#serviceinventory";
    }
    sections.forEach(({ link, hash: sectionHash }) => {
      const isActive = sectionHash === normalizedHash;
      link.classList.toggle("is-active", isActive);
      if (isActive) {
        link.setAttribute("aria-current", "page");
      } else {
        link.removeAttribute("aria-current");
      }
    });
  }

  const observer = new IntersectionObserver(entries => {
    const visibleEntries = entries
      .filter(entry => entry.isIntersecting)
      .sort((a, b) => b.intersectionRatio - a.intersectionRatio);

    if (visibleEntries.length === 0) {
      return;
    }

    const activeSection = sections.find(({ section }) => section === visibleEntries[0].target);
    if (activeSection) {
      setActiveLink(activeSection.hash);
    }
  }, {
    rootMargin: "-25% 0px -55% 0px",
    threshold: [0.2, 0.35, 0.5]
  });

  sections.forEach(({ section }) => observer.observe(section));

  navLinks.forEach(link => {
    link.addEventListener("click", () => {
      const hash = link.getAttribute("href");
      if (hash) {
        setActiveLink(hash);
      }
    });
  });

  setActiveLink(window.location.hash || sections[0].hash);
}

function isEditableShortcutTarget(target) {
  if (!(target instanceof HTMLElement)) {
    return false;
  }

  const tagName = target.tagName;
  return target.isContentEditable ||
    tagName === "INPUT" ||
    tagName === "TEXTAREA" ||
    tagName === "SELECT";
}

function getSectionSearchInput(selector) {
  const tableElement = selector ? document.querySelector(selector) : null;
  if (!tableElement) {
    return null;
  }

  const wrapper = tableElement.closest(".dt-container, .dataTables_wrapper");
  if (!wrapper) {
    return null;
  }

  return wrapper.querySelector(".dataTables_filter input, .dt-search input");
}

function focusActiveSectionSearch() {
  const activeLink = document.querySelector("#navbarNav .navbar-nav.me-auto .nav-link[aria-current='page']");
  const activeHash = activeLink ? activeLink.getAttribute("href") : "";
  const selectorBySection = {
    "#scannedhosts": "#table-overview",
    "#openservices": "#table-services",
    "#serviceinventory": "#service-inventory"
  };
  const searchInput = getSectionSearchInput(selectorBySection[activeHash || ""]);
  if (!searchInput) {
    return false;
  }

  searchInput.focus();
  if (typeof searchInput.select === "function") {
    searchInput.select();
  }
  return true;
}

function initializeSlashSearchShortcut() {
  document.addEventListener("keydown", event => {
    if (event.key !== "/" || event.ctrlKey || event.metaKey || event.altKey) {
      return;
    }

    if (isEditableShortcutTarget(event.target)) {
      return;
    }

    if (focusActiveSectionSearch()) {
      event.preventDefault();
    }
  });
}

function openLinkedHost(hash) {
  if (!hash || !hash.startsWith("#onlinehosts-")) {
    return null;
  }

  const target = document.querySelector(hash);
  if (!target) {
    return null;
  }

  const hostEntry = target.closest("details");
  if (hostEntry) {
    hostEntry.open = true;
  }

  return target;
}

function openLinkedServiceVariant(hash) {
  if (!hash || !hash.startsWith("#servicevariant-")) {
    return null;
  }

  const target = document.querySelector(hash);
  if (!target) {
    return null;
  }

  openAncestorDetails(target);
  return target;
}

function openAncestorDetails(target) {
  let current = target ? target.parentElement : null;
  while (current) {
    if (current.tagName === "DETAILS") {
      current.open = true;
    }
    current = current.parentElement;
  }
}

function getReportScrollTop(target) {
  if (!target) {
    return 0;
  }

  const headerOffset = 60;
  const top = target.getBoundingClientRect().top + window.pageYOffset - headerOffset;
  return Math.max(0, top);
}

function scrollToReportTarget(target) {
  if (!target) {
    return;
  }

  window.scrollTo(0, getReportScrollTop(target));
}

function pinReportToSummaryView() {
  const summary = document.getElementById("summary");
  if (summary) {
    scrollToReportTarget(summary);
    return;
  }

  window.scrollTo(0, 0);
}

function navigateToInitialHash() {
  const hash = window.location.hash;
  if (!hash || hash === "#summary") {
    return;
  }

  const hostTarget = openLinkedHost(hash);
  if (hostTarget) {
    scrollToReportTarget(hostTarget);
    return;
  }

  const serviceVariantTarget = openLinkedServiceVariant(hash);
  if (serviceVariantTarget) {
    scrollToReportTarget(serviceVariantTarget);
    return;
  }

  const target = document.querySelector(hash);
  if (target) {
    openAncestorDetails(target);
    scrollToReportTarget(target);
  }
}

function setReportLoadingOverlayVisible(isVisible, titleText = "Preparing Report") {
  const overlay = document.getElementById("reportLoadingOverlay");
  const title = document.getElementById("reportLoadingTitleText");
  if (!overlay) {
    return;
  }

  if (title) {
    title.textContent = titleText;
  }

  overlay.classList.toggle("is-hidden", !isVisible);
  overlay.setAttribute("aria-hidden", isVisible ? "false" : "true");
}

function finalizeReportInitialization() {
  window.requestAnimationFrame(() => {
    window.requestAnimationFrame(() => {
      document.body.classList.remove("report-initializing");
      setReportLoadingOverlayVisible(false);
      navigateToInitialHash();
    });
  });
}

function getDataTableHeaderOffset() {
  const navbar = document.getElementById("mainNavbar");
  return navbar ? Math.ceil(navbar.getBoundingClientRect().height) : 0;
}

function getHostOverviewTableRows() {
  return getTableRows("table-overview", { requireAddress: true });
}

function getVisibleHostOverviewRows() {
  return getTableRows("table-overview", { searchApplied: true, requireAddress: true });
}

function setEquals(left, right) {
  if (left.size !== right.size) {
    return false;
  }

  for (const value of left) {
    if (!right.has(value)) {
      return false;
    }
  }

  return true;
}

function syncHostScopeSummary() {
  const summary = document.getElementById("hostScopeSummary");
  if (!summary) {
    return;
  }

  const state = getHostScopeState();
  const selectedCount = state.pendingSelectedHosts.size;
  const totalCount = state.allHosts.size;
  summary.textContent = `${selectedCount} of ${totalCount} host${totalCount === 1 ? "" : "s"} selected${state.dirty ? " · apply pending" : ""}`;
}

function syncHostScopeApplyButton() {
  const button = document.getElementById("applyHostScopeButton");
  if (!button) {
    return;
  }

  const state = getHostScopeState();
  button.disabled = !state.dirty || state.redrawInProgress;
}

function syncHostScopeCheckboxesAndRows() {
  const state = getHostScopeState();
  getHostOverviewTableRows().forEach(row => {
    const address = normalizeHostAddress(row.dataset.address);
    const checkbox = row.querySelector(".host-scope-checkbox");
    const scopeCell = checkbox ? checkbox.closest(".host-scope-cell") : null;
    const isSelected = !address || state.pendingSelectedHosts.has(address);

    row.classList.toggle("host-scope-excluded", Boolean(address) && !isSelected);
    if (checkbox) {
      checkbox.checked = isSelected;
    }
    if (scopeCell) {
      scopeCell.dataset.order = isSelected ? "1" : "0";
      scopeCell.dataset.search = isSelected ? "Included" : "Excluded";
    }
  });

  const overviewTable = document.getElementById("table-overview");
  if (overviewTable && window.jQuery && $.fn.dataTable && $.fn.dataTable.isDataTable(overviewTable)) {
    const tableApi = $(overviewTable).DataTable();
    if (tableApi) {
      tableApi.rows().invalidate("dom").draw(false);
    }
  }

  syncHostScopeSummary();
  syncHostScopeApplyButton();
}

function registerHostScopeDataTableFilter() {
  const state = getHostScopeState();
  if (state.dataTableFilterRegistered || !(window.jQuery && $.fn.dataTable)) {
    return;
  }

  $.fn.dataTable.ext.search.push((settings, _searchData, dataIndex) => {
    const tableId = settings && settings.nTable ? settings.nTable.id : "";
    if (tableId !== "table-services") {
      return true;
    }

    const row = settings.aoData && settings.aoData[dataIndex] ? settings.aoData[dataIndex].nTr : null;
    const address = row ? normalizeHostAddress(row.dataset.address) : "";
    return !address || isHostInScope(address);
  });

  state.dataTableFilterRegistered = true;
}

function recalculateOpenServiceMetrics() {
  const table = document.getElementById("table-services");
  if (!table) {
    return;
  }

  const headers = Array.from(table.querySelectorAll("thead th")).map(header => (header.textContent || "").trim());
  const countColumnIndex = headers.indexOf("Count");
  const serviceColumnIndex = headers.indexOf("Service");
  if (countColumnIndex === -1 || serviceColumnIndex === -1) {
    return;
  }

  const selectedCounts = new Map();
  const rows = getTableRows("table-services", { requireAddress: true });

  rows.forEach(row => {
    if (!isHostInScope(row.dataset.address)) {
      return;
    }

    const cells = row.querySelectorAll("td");
    if (cells.length <= serviceColumnIndex) {
      return;
    }

    const serviceText = (cells[serviceColumnIndex].textContent || "").trim().toLowerCase();
    const key = `${serviceText}|${row.dataset.portid || ""}|${row.dataset.protocol || ""}`;
    selectedCounts.set(key, (selectedCounts.get(key) || 0) + 1);
  });

  rows.forEach(row => {
    const cells = row.querySelectorAll("td");
    if (cells.length <= countColumnIndex || cells.length <= serviceColumnIndex) {
      return;
    }

    const serviceText = (cells[serviceColumnIndex].textContent || "").trim().toLowerCase();
    const key = `${serviceText}|${row.dataset.portid || ""}|${row.dataset.protocol || ""}`;
    const count = selectedCounts.get(key) || 0;
    cells[countColumnIndex].dataset.order = String(count);
    cells[countColumnIndex].textContent = String(count);
  });
}

function refreshOpenServicesForHostScope() {
  const tableElement = document.getElementById("table-services");
  if (!tableElement) {
    return;
  }

  recalculateOpenServiceMetrics();

  if (window.jQuery && $.fn.dataTable && $.fn.dataTable.isDataTable(tableElement)) {
    const tableApi = $(tableElement).DataTable();
    if (tableApi) {
      tableApi.rows().invalidate("dom").draw(false);
      tableApi.columns.adjust();
      if (tableApi.fixedHeader && typeof tableApi.fixedHeader.adjust === "function") {
        tableApi.fixedHeader.adjust();
      }
    }
  }
}

function updateHostDetailsVisibility() {
  const hostEntries = document.querySelectorAll("#onlinehosts-list details.host-entry");
  hostEntries.forEach(entry => {
    const address = normalizeHostAddress(entry.dataset.address);
    const isSelected = !address || isHostInScope(address);
    entry.hidden = !isSelected;
    if (!isSelected) {
      entry.open = false;
    }
  });
}

function refreshServiceInventoryForHostScope() {
  const tableElement = document.getElementById("service-inventory");
  if (!tableElement) {
    return;
  }

  let searchValue = "";
  let orderValue = null;

  if (window.jQuery && $.fn.dataTable && $.fn.dataTable.isDataTable(tableElement)) {
    const tableApi = $(tableElement).DataTable();
    if (tableApi) {
      searchValue = tableApi.search();
      orderValue = tableApi.order();
      tableApi.destroy();
    }
  }

  buildServiceInventoryTable();
  initializeServiceInventoryToggle();

  const detachedNestedTables = detachServiceInventoryNestedTables();
  const tableApi = initializeDataTable("#service-inventory");
  restoreServiceInventoryNestedTables(detachedNestedTables);
  initializeServiceInventoryNestedTables();
  if (tableApi) {
    if (searchValue) {
      tableApi.search(searchValue);
    }
    if (Array.isArray(orderValue) && orderValue.length > 0) {
      tableApi.order(orderValue);
    }
    tableApi.draw(false);
  }
}

function updateSummaryForHostScope() {
  const selectedHostRows = getHostOverviewTableRows()
    .filter(row => isHostInScope(row.dataset.address));
  const selectedUpCount = selectedHostRows
    .filter(row => normalizeHostAddress(row.dataset.state) === "up")
    .length;
  const selectedDownCount = selectedHostRows.length - selectedUpCount;
  const selectedOpenServiceRows = getTableRows("table-services", { requireAddress: true })
    .filter(row => isHostInScope(row.dataset.address));
  const selectedMatrixHosts = Array.from(document.querySelectorAll("#matrixCount .host"))
    .filter(entry => isHostInScope(entry.dataset.address));

  const uniqueServices = new Set();
  const portProtocolCounts = new Map();
  const rareServices = new Set();
  const serviceFrequency = new Map();

  selectedMatrixHosts.forEach(host => {
    const hostServices = new Set();
    host.querySelectorAll(".port").forEach(portElement => {
      const serviceKey = normalizeUniquenessService(portElement.dataset.service || "");
      const portKey = `${normalizeHostAddress(portElement.dataset.port)}|${serviceKey.split(":")[0] || ""}`;
      if (!serviceKey) {
        return;
      }

      uniqueServices.add(serviceKey);
      hostServices.add(serviceKey);
      portProtocolCounts.set(portKey, (portProtocolCounts.get(portKey) || 0) + 1);
    });

    hostServices.forEach(serviceKey => {
      serviceFrequency.set(serviceKey, (serviceFrequency.get(serviceKey) || 0) + 1);
    });
  });

  selectedMatrixHosts.forEach(host => {
    host.querySelectorAll(".port").forEach(portElement => {
      const serviceKey = normalizeUniquenessService(portElement.dataset.service || "");
      const portKey = `${normalizeHostAddress(portElement.dataset.port)}|${serviceKey.split(":")[0] || ""}`;
      if (serviceKey && (portProtocolCounts.get(portKey) || 0) === 1) {
        rareServices.add(serviceKey);
      }
    });
  });

  const openPortsValue = document.getElementById("summaryOpenPortsValue");
  const uniqueServicesValue = document.getElementById("summaryUniqueServicesValue");
  const rareServicesValue = document.getElementById("summaryRareServicesValue");
  const serviceEntropyValue = document.getElementById("summaryServiceEntropyValue");
  const upHostsBar = document.getElementById("summaryUpHostsBar");
  const downHostsBar = document.getElementById("summaryDownHostsBar");
  const totalSelectedHosts = selectedHostRows.length;
  const upWidth = totalSelectedHosts > 0 ? (selectedUpCount / totalSelectedHosts) * 100 : 0;
  const downWidth = totalSelectedHosts > 0 ? (selectedDownCount / totalSelectedHosts) * 100 : 0;
  const totalServiceObservations = Array.from(serviceFrequency.values())
    .reduce((sum, count) => sum + count, 0);
  const serviceEntropy = totalServiceObservations > 0
    ? Array.from(serviceFrequency.values()).reduce((sum, count) => {
      const probability = count / totalServiceObservations;
      return probability > 0 ? sum - (probability * Math.log2(probability)) : sum;
    }, 0)
    : 0;

  if (openPortsValue) {
    openPortsValue.textContent = String(selectedOpenServiceRows.length);
  }
  if (uniqueServicesValue) {
    uniqueServicesValue.textContent = String(uniqueServices.size);
  }
  if (rareServicesValue) {
    rareServicesValue.textContent = String(rareServices.size);
  }
  if (serviceEntropyValue) {
    serviceEntropyValue.textContent = totalServiceObservations > 0 ? serviceEntropy.toFixed(2) : "N/A";
  }
  if (upHostsBar) {
    upHostsBar.style.width = `${upWidth}%`;
    upHostsBar.setAttribute("aria-valuenow", String(Math.round(upWidth)));
    upHostsBar.textContent = `${selectedUpCount} Hosts up`;
  }
  if (downHostsBar) {
    downHostsBar.style.width = `${downWidth}%`;
    downHostsBar.setAttribute("aria-valuenow", String(Math.round(downWidth)));
    downHostsBar.textContent = `${selectedDownCount} Hosts down`;
  }
}

function applyHostScopeSelection() {
  setReportLoadingOverlayVisible(true, "Updating Report");
  syncHostScopeCheckboxesAndRows();
  updateHostDetailsVisibility();
  initializeHostToggle();

  window.requestAnimationFrame(() => {
    refreshOpenServicesForHostScope();
    updateSummaryForHostScope();
    initializeHostUniquenessScores();

    window.requestAnimationFrame(() => {
      refreshServiceInventoryForHostScope();

      window.requestAnimationFrame(() => {
        if (typeof window.renderServiceDistributionVisualizations === "function") {
          window.renderServiceDistributionVisualizations();
        }

        if (typeof window.renderMatrixVisualizations === "function") {
          window.renderMatrixVisualizations();
        }

        syncDataTableFixedHeaders();
        const state = getHostScopeState();
        state.redrawInProgress = false;
        syncHostScopeApplyButton();
        setReportLoadingOverlayVisible(false, "Preparing Report");
      });
    });
  });
}

function initializeHostScopeControls() {
  const controls = document.getElementById("hostScopeControls");
  const table = document.getElementById("table-overview");
  if (!controls || !table || table.dataset.hostScopeInitialized === "true") {
    return;
  }

  const state = getHostScopeState();
  const rows = getHostOverviewTableRows();
  const addresses = rows
    .map(row => normalizeHostAddress(row.dataset.address))
    .filter(Boolean);

  state.allHosts = new Set(addresses);
  state.selectedHosts = new Set(addresses);
  state.pendingSelectedHosts = new Set(addresses);
  state.dirty = false;
  registerHostScopeDataTableFilter();
  syncHostScopeCheckboxesAndRows();

  table.addEventListener("change", event => {
    const checkbox = event.target.closest(".host-scope-checkbox");
    if (!checkbox) {
      return;
    }

    const address = normalizeHostAddress(checkbox.dataset.address);
    if (!address) {
      return;
    }

    if (checkbox.checked) {
      state.pendingSelectedHosts.add(address);
    } else {
      state.pendingSelectedHosts.delete(address);
    }

    state.dirty = !setEquals(state.pendingSelectedHosts, state.selectedHosts);
    syncHostScopeCheckboxesAndRows();
  });

  const selectVisibleButton = document.getElementById("selectVisibleHostsButton");
  if (selectVisibleButton) {
    selectVisibleButton.addEventListener("click", () => {
      getVisibleHostOverviewRows().forEach(row => {
        const address = normalizeHostAddress(row.dataset.address);
        if (address) {
          state.pendingSelectedHosts.add(address);
        }
      });
      state.dirty = !setEquals(state.pendingSelectedHosts, state.selectedHosts);
      syncHostScopeCheckboxesAndRows();
    });
  }

  const clearVisibleButton = document.getElementById("clearVisibleHostsButton");
  if (clearVisibleButton) {
    clearVisibleButton.addEventListener("click", () => {
      getVisibleHostOverviewRows().forEach(row => {
        const address = normalizeHostAddress(row.dataset.address);
        if (address) {
          state.pendingSelectedHosts.delete(address);
        }
      });
      state.dirty = !setEquals(state.pendingSelectedHosts, state.selectedHosts);
      syncHostScopeCheckboxesAndRows();
    });
  }

  const applyButton = document.getElementById("applyHostScopeButton");
  if (applyButton) {
    applyButton.addEventListener("click", () => {
      if (state.redrawInProgress) {
        return;
      }

      state.selectedHosts = new Set(state.pendingSelectedHosts);
      state.dirty = false;
      state.redrawInProgress = true;
      syncHostScopeCheckboxesAndRows();
      applyHostScopeSelection();
    });
  }

  table.dataset.hostScopeInitialized = "true";
}

function initializeHostToggle() {
  const toggle = document.getElementById("toggle-all-hosts");
  const hostList = document.getElementById("onlinehosts-list");
  if (!toggle || !hostList) return;

  function getVisibleHostEntries() {
    return Array.from(hostList.querySelectorAll("details.host-entry"))
      .filter(entry => !entry.hidden);
  }

  function syncLabel() {
    const hostEntries = getVisibleHostEntries();
    toggle.hidden = hostEntries.length === 0;
    if (hostEntries.length === 0) {
      return;
    }
    const allOpen = hostEntries.every(entry => entry.open);
    toggle.setAttribute("aria-expanded", allOpen ? "true" : "false");
    toggle.setAttribute("title", allOpen ? "Collapse all visible host details" : "Expand all visible host details");
  }

  window.refreshHostToggleLabel = syncLabel;

  if (toggle.dataset.hostToggleInitialized !== "true") {
    toggle.addEventListener("click", () => {
      const hostEntries = getVisibleHostEntries();
      if (hostEntries.length === 0) {
        return;
      }
      const shouldOpen = !hostEntries.every(entry => entry.open);
      hostEntries.forEach(entry => {
        entry.open = shouldOpen;
      });
      syncLabel();
    });
    toggle.dataset.hostToggleInitialized = "true";
  }

  Array.from(hostList.querySelectorAll("details.host-entry")).forEach(entry => {
    if (entry.dataset.hostToggleBound === "true") {
      return;
    }

    entry.addEventListener("toggle", () => {
      if (typeof window.refreshHostToggleLabel === "function") {
        window.refreshHostToggleLabel();
      }
    });
    entry.dataset.hostToggleBound = "true";
  });

  syncLabel();
}

function initializeServiceInventoryToggle() {
  const toggle = document.getElementById("toggle-all-service-inventory");
  const tableBody = document.getElementById("serviceInventoryTableBody");
  if (!toggle || !tableBody) return;

  function getServiceEntries() {
    return Array.from(tableBody.querySelectorAll("details.service-inventory-service-details"));
  }

  function syncLabel() {
    const serviceEntries = getServiceEntries();
    toggle.hidden = serviceEntries.length === 0;
    if (serviceEntries.length === 0) {
      return;
    }
    const allOpen = serviceEntries.every(entry => entry.open);
    toggle.setAttribute("aria-expanded", allOpen ? "true" : "false");
    toggle.setAttribute("title", allOpen ? "Collapse all visible service details" : "Expand all visible service details");
  }

  window.refreshServiceInventoryToggleLabel = syncLabel;

  if (toggle.dataset.serviceInventoryToggleInitialized !== "true") {
    toggle.addEventListener("click", () => {
      const serviceEntries = getServiceEntries();
      if (serviceEntries.length === 0) {
        return;
      }
      const shouldOpen = !serviceEntries.every(entry => entry.open);
      serviceEntries.forEach(entry => {
        entry.open = shouldOpen;
      });
      syncLabel();
    });
    toggle.dataset.serviceInventoryToggleInitialized = "true";
  }

  Array.from(tableBody.querySelectorAll("details.service-inventory-service-details")).forEach(entry => {
    if (entry.dataset.serviceInventoryToggleBound === "true") {
      return;
    }

    entry.addEventListener("toggle", () => {
      if (typeof window.refreshServiceInventoryToggleLabel === "function") {
        window.refreshServiceInventoryToggleLabel();
      }
    });
    entry.dataset.serviceInventoryToggleBound = "true";
  });

  syncLabel();
}

function syncDataTableFixedHeaders() {
  if (!(window.jQuery && $.fn.dataTable)) {
    return;
  }

  const tables = $.fn.dataTable.tables({ visible: true });
  if (!tables || tables.length === 0) {
    return;
  }

  const headerOffset = getDataTableHeaderOffset();

  Array.from(tables).forEach(table => {
    const api = $(table).DataTable();
    if (!api || !api.fixedHeader) {
      return;
    }

    if (typeof api.fixedHeader.headerOffset === "function") {
      api.fixedHeader.headerOffset(headerOffset);
    }

    if (typeof api.fixedHeader.adjust === "function") {
      api.fixedHeader.adjust();
    }
  });
}

function normalizeIpv6SortValue(address) {
  let value = (address || "").trim().toLowerCase();
  if (!value) {
    return "";
  }

  const zoneIndex = value.indexOf("%");
  if (zoneIndex !== -1) {
    value = value.slice(0, zoneIndex);
  }

  if (value.includes(".")) {
    const lastColonIndex = value.lastIndexOf(":");
    const ipv4Part = lastColonIndex === -1 ? value : value.slice(lastColonIndex + 1);

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ipv4Part)) {
      const octets = ipv4Part.split(".").map(part => Number.parseInt(part, 10));
      if (octets.every(octet => Number.isInteger(octet) && octet >= 0 && octet <= 255)) {
        const high = ((octets[0] << 8) | octets[1]).toString(16);
        const low = ((octets[2] << 8) | octets[3]).toString(16);
        value = `${lastColonIndex === -1 ? "" : value.slice(0, lastColonIndex)}:${high}:${low}`;
      }
    }
  }

  const parts = value.split("::");
  if (parts.length > 2) {
    return `z-${value}`;
  }

  const left = parts[0] ? parts[0].split(":").filter(Boolean) : [];
  const right = parts.length === 2 && parts[1] ? parts[1].split(":").filter(Boolean) : [];
  const missingGroups = 8 - (left.length + right.length);

  if ((parts.length === 1 && left.length !== 8) || missingGroups < 0) {
    return `z-${value}`;
  }

  const expanded = parts.length === 2
    ? [...left, ...Array.from({ length: missingGroups }, () => "0"), ...right]
    : left;

  if (expanded.length !== 8) {
    return `z-${value}`;
  }

  return `6-${expanded.map(part => part.padStart(4, "0")).join(":")}`;
}

function normalizeIpSortValue(rawValue) {
  const value = (rawValue || "").trim().replace(/^\[/, "").replace(/\]$/, "");
  if (!value || value.toLowerCase() === "n/a") {
    return "";
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) {
    const octets = value.split(".").map(part => Number.parseInt(part, 10));
    if (octets.every(octet => Number.isInteger(octet) && octet >= 0 && octet <= 255)) {
      return `4-${octets.map(octet => String(octet).padStart(3, "0")).join(".")}`;
    }
  }

  if (value.includes(":")) {
    return normalizeIpv6SortValue(value);
  }

  return `z-${value.toLowerCase()}`;
}

function applyAddressSortKeys(tableElement) {
  if (!tableElement) {
    return;
  }

  const headers = Array.from(tableElement.querySelectorAll("thead th")).map(header => ($(header).text() || '').trim());
  const addressColumnIndex = headers.indexOf("Address");
  if (addressColumnIndex === -1) {
    return;
  }

  tableElement.querySelectorAll("tbody tr").forEach(row => {
    const cells = row.querySelectorAll("td");
    if (cells.length <= addressColumnIndex) {
      return;
    }

    const addressCell = cells[addressColumnIndex];
    const addressText = (addressCell.textContent || "").trim();
    const sortValue = normalizeIpSortValue(addressText);
    if (sortValue) {
      addressCell.dataset.order = sortValue;
    }
  });
}

function unescapeRegex(text) {
  return (text || "").replace(/\\([.*+?^${}()|[\]\\])/g, "$1");
}

function extractExactSearchValue(searchValue) {
  const match = /^\^([\s\S]*)\$$/.exec(searchValue || "");
  return match ? unescapeRegex(match[1]) : "";
}

function isSignificantServiceValue(service) {
  const normalized = (service || "").trim().toLowerCase();
  return normalized !== "" && normalized !== "unknown" && normalized !== "ssl/unknown";
}

function syncDataTableSearchInputState(table, wrapper) {
  if (!table || !wrapper) {
    return;
  }

  const searchInput = wrapper.querySelector(".dataTables_filter input, .dt-search input");
  if (!searchInput) {
    return;
  }

  const hasActiveSearch = String(table.search() || "").trim() !== "";
  searchInput.classList.toggle("datatable-filter-active", hasActiveSearch);
}

function resolveDataTableResetScrollTarget(table, selector) {
  const sectionIdsBySelector = {
    "#table-services": "openservices",
    "#table-overview": "scannedhosts",
    "#service-inventory": "serviceinventory"
  };

  const mappedSectionId = sectionIdsBySelector[selector];
  if (mappedSectionId) {
    const mappedSection = document.getElementById(mappedSectionId);
    if (mappedSection) {
      return mappedSection;
    }
  }

  const tableNode = table && typeof table.table === "function" ? table.table().node() : null;
  const tableWrapper = tableNode ? tableNode.closest(".table-responsive") : null;
  let current = tableWrapper || tableNode;
  while (current) {
    let sibling = current.previousElementSibling;
    while (sibling) {
      if (/^H[1-6]$/.test(sibling.tagName)) {
        return sibling;
      }
      sibling = sibling.previousElementSibling;
    }
    current = current.parentElement;
  }

  return tableNode;
}

function resetDataTableExpandedState(selector) {
  if (selector !== "#service-inventory") {
    return;
  }

  const serviceInventoryTableBody = document.getElementById("serviceInventoryTableBody");
  if (!serviceInventoryTableBody) {
    return;
  }

  serviceInventoryTableBody.querySelectorAll("details[open]").forEach(details => {
    details.open = false;
  });
}

function initializeDataTableResetButton(table, wrapper, selector, defaultOrder) {
  if (!table || !wrapper) {
    return;
  }

  const resetContainer = wrapper.querySelector(".datatable-footer-end");
  if (!resetContainer || resetContainer.querySelector(".datatable-reset-button")) {
    return;
  }

  const resetButton = document.createElement("button");
  resetButton.type = "button";
  resetButton.className = "btn btn-outline-secondary btn-sm datatable-reset-button";
  resetButton.textContent = "Reset";
  resetButton.setAttribute("aria-label", "Reset table filters and sort order");
  resetContainer.appendChild(resetButton);

  resetButton.addEventListener("click", () => {
    const searchInput = wrapper.querySelector(".dataTables_filter input, .dt-search input");
    if (searchInput) {
      searchInput.value = "";
      searchInput.classList.remove("datatable-filter-active");
    }

    const serviceFilter = wrapper.querySelector(".datatable-inline-filter .form-select");
    if (serviceFilter) {
      serviceFilter.value = "";
      serviceFilter.classList.remove("datatable-filter-active");
      serviceFilter.dispatchEvent(new Event("change", { bubbles: true }));
    }

    table.search("");
    table.columns().search("");
    table.order((defaultOrder || [[0, "desc"]]).map(([columnIndex, direction]) => [Number(columnIndex), direction]));
    table.page("first").draw();
    resetDataTableExpandedState(selector);

    const resetScrollTarget = resolveDataTableResetScrollTarget(table, selector);
    if (resetScrollTarget) {
      window.requestAnimationFrame(() => {
        window.scrollTo({
          top: getReportScrollTop(resetScrollTarget),
          behavior: "smooth"
        });
      });
    }
  });
}

function initializeServiceDropdownFilter(table, tableElement, options = {}) {
  if (!table || !tableElement) {
    return;
  }

  const tableLabel = options.tableLabel || "services";

  const wrapper = table.table().container();
  if (!wrapper) {
    return;
  }

  const headers = Array.from(tableElement.querySelectorAll("thead th")).map(header => ($(header).text() || "").trim());
  const serviceColumnIndex = headers.indexOf("Service");
  const productColumnIndex = headers.indexOf("Product");
  const versionColumnIndex = headers.indexOf("Version");
  if (serviceColumnIndex === -1 || productColumnIndex === -1 || versionColumnIndex === -1) {
    return;
  }

  const searchContainer = wrapper.querySelector(".dataTables_filter, .dt-search");
  if (!searchContainer) {
    return;
  }

  const serviceCounts = new Map();

  table
    .column(serviceColumnIndex, { search: "none", order: "index" })
    .data()
    .toArray()
    .map(value => $("<div>").html(value).text().trim())
    .filter(isSignificantServiceValue)
    .forEach(service => {
      serviceCounts.set(service, (serviceCounts.get(service) || 0) + 1);
    });

  const serviceEntries = Array.from(serviceCounts.entries())
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0], undefined, {
      numeric: true,
      sensitivity: "base"
    }));
  const services = serviceEntries.map(([service]) => service);

  if (services.length === 0) {
    return;
  }

  const filterId = `${tableElement.id || "table-services"}-service-filter`;
  const container = document.createElement("div");
  const label = document.createElement("label");
  const select = document.createElement("select");
  const defaultOrder = [[0, "desc"]];
  let activeServiceFilter = "";
  let lastUnfilteredOrder = defaultOrder;

  container.className = "datatable-inline-filter";
  label.className = "datatable-inline-filter-label";
  label.htmlFor = filterId;
  label.textContent = "Service";
  select.className = "form-select form-select-sm";
  select.id = filterId;
  select.setAttribute("aria-label", `Filter ${tableLabel} by service name`);

  const allOption = document.createElement("option");
  allOption.value = "";
  allOption.textContent = "All services";
  select.appendChild(allOption);

  serviceEntries.forEach(([service, count]) => {
    const option = document.createElement("option");
    option.value = service;
    option.textContent = `${service} (${count})`;
    select.appendChild(option);
  });

  container.appendChild(label);
  container.appendChild(select);
  searchContainer.appendChild(container);

  const loadedState = typeof table.state === "function" ? table.state.loaded() : null;
  const loadedColumnSearch = loadedState && Array.isArray(loadedState.columns) && loadedState.columns[serviceColumnIndex]
    ? loadedState.columns[serviceColumnIndex].search.search
    : "";
  const currentColumnSearch = table.column(serviceColumnIndex).search();
  const initialServiceFilter = extractExactSearchValue(loadedColumnSearch || currentColumnSearch);
  const initialOrder = loadedState && Array.isArray(loadedState.order) && loadedState.order.length > 0
    ? loadedState.order
    : table.order();

  if (!initialServiceFilter && Array.isArray(initialOrder) && initialOrder.length > 0) {
    lastUnfilteredOrder = initialOrder.map(([columnIndex, direction]) => [Number(columnIndex), direction]);
  }

  function applyServiceFilter(service) {
    activeServiceFilter = service || "";
    select.classList.toggle("datatable-filter-active", activeServiceFilter !== "");

    if (activeServiceFilter) {
      table
        .column(serviceColumnIndex)
        .search(`^${escapeRegex(activeServiceFilter)}$`, true, false);
      table
        .order([
          [productColumnIndex, "asc"],
          [versionColumnIndex, "asc"]
        ])
        .draw();
      return;
    }

    table
      .column(serviceColumnIndex)
      .search("");
    table
      .order(lastUnfilteredOrder)
      .draw();
  }

  table.on("order.dt", function () {
    if (activeServiceFilter) {
      return;
    }
    const currentOrder = table.order();
    if (Array.isArray(currentOrder) && currentOrder.length > 0) {
      lastUnfilteredOrder = currentOrder.map(([columnIndex, direction]) => [Number(columnIndex), direction]);
    }
  });

  select.addEventListener("change", event => {
    applyServiceFilter(event.target.value);
  });

  if (initialServiceFilter && services.includes(initialServiceFilter)) {
    select.value = initialServiceFilter;
    applyServiceFilter(initialServiceFilter);
  } else {
    select.classList.remove("datatable-filter-active");
  }
}

function initializeDataTable(selector) {
  const exportNames = {
    "#table-services": "nmapview-open-services",
    "#table-overview": "nmapview-scanned-hosts",
    "#service-inventory": "nmapview-service-inventory"
  };
  const exportName = exportNames[selector] || "nmapview-table-export";
  const defaultOrders = {
    "#table-services": [[2, "asc"], [1, "asc"]],
    "#service-inventory": [[0, "desc"]]
  };
  const buttons = [];

  if (selector !== '#service-inventory') {
    buttons.push(
      {
        extend: 'colvis',
        text: 'Columns',
        className: 'btn btn-light'
      },
      {
        extend: 'csvHtml5',
        text: 'CSV',
        filename: exportName,
        fieldSeparator: ';',
        exportOptions: { columns: getDataTableExportColumnSelector(), orthogonal: 'export' },
        className: 'btn btn-light'
      },
      {
        extend: 'excelHtml5',
        text: 'Excel',
        filename: exportName,
        autoFilter: true,
        exportOptions: { columns: getDataTableExportColumnSelector(), orthogonal: 'export' },
        className: 'btn btn-light'
      },
      {
        text: 'JSON',
        className: 'btn btn-light',
        action: function (e, dt, node, config) {
          const visibleColumns = dt.columns(getDataTableExportColumnSelector());
          const headerIndexes = visibleColumns.indexes().toArray();
          const headers = visibleColumns.header().toArray().map(h => $(h).text().trim());

          const data = dt.rows({ search: 'applied' }).nodes().toArray()
            .filter(row => isRowIncludedInCurrentExportScope(row))
            .map(row => {
            const obj = {};
            headerIndexes.forEach((columnIndex, i) => {
              const cell = $(row).find('td').get(columnIndex);
              obj[headers[i]] = cell ? $(cell).text().trim() : '';
            });
            return obj;
          });

          const json = JSON.stringify(data, null, 2);
          const blob = new Blob([json], { type: 'application/json' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `${exportName}.json`;
          a.click();
          URL.revokeObjectURL(url);
        }
      }
    );

    if (selector !== '#table-services' && selector !== '#table-overview') {
      buttons.splice(1, 0, {
        extend: 'copyHtml5',
        text: 'Copy',
        title: exportName,
        exportOptions: { rows: getDataTableExportRowSelector(), columns: getDataTableExportColumnSelector(), orthogonal: 'export' },
        className: 'btn btn-light'
      });
    }
  }

  if (selector === '#table-services') {
    buttons.push({
      extend: 'collection',
      text: 'Copy',
      className: 'btn btn-light',
      buttons: [
        {
          text: 'All',
          action: async function (e, dt) {
            await copyVisibleDataTableRows(dt);
          }
        },
        {
          text: 'IPs',
          action: async function (e, dt) {
            const addresses = [];

            getScopedDataTableRows(dt).forEach(row => {
              const cells = $(row).find('td');
              const address = ($(cells.get(1)).text() || '').trim();

              if (address) {
                addresses.push(address);
              }
            });

            const uniqueAddresses = [...new Set(addresses)]
              .sort((left, right) => left.localeCompare(right, undefined, {
                numeric: true,
                sensitivity: 'base'
              }));

            await copyTextWithFeedback(
              uniqueAddresses.join('\n'),
              `Copied ${uniqueAddresses.length} IP${uniqueAddresses.length === 1 ? "" : "s"}`
            );
          }
        },
        {
          text: 'Ports',
          action: async function (e, dt) {
            const ports = [];

            getScopedDataTableRows(dt).forEach(row => {
              const cells = $(row).find('td');
              const port = ($(cells.get(2)).text() || '').trim();

              if (port) {
                ports.push(port);
              }
            });

            const uniquePorts = [...new Set(ports)]
              .sort((left, right) => Number(left) - Number(right) || left.localeCompare(right, undefined, {
                numeric: true,
                sensitivity: 'base'
              }));

            await copyTextWithFeedback(
              uniquePorts.join(','),
              `Copied ${uniquePorts.length} port${uniquePorts.length === 1 ? "" : "s"}`
            );
          }
        },
        {
          text: 'IP:Ports',
          action: async function (e, dt) {
            const endpoints = [];

            getScopedDataTableRows(dt).forEach(row => {
              const cells = $(row).find('td');
              const address = ($(cells.get(1)).text() || '').trim();
              const port = ($(cells.get(2)).text() || '').trim();

              if (address && port) {
                endpoints.push(`${address}:${port}`);
              }
            });

            const uniqueEndpoints = [...new Set(endpoints)];
            await copyTextWithFeedback(
              uniqueEndpoints.join('\n'),
              `Copied ${uniqueEndpoints.length} IP:Port entr${uniqueEndpoints.length === 1 ? "y" : "ies"}`
            );
          }
        }
      ]
    });
  }

  if (selector === '#table-overview') {
    buttons.push({
      extend: 'collection',
      text: 'Copy',
      className: 'btn btn-light',
      buttons: [
        {
          text: 'All',
          action: async function (e, dt) {
            await copyVisibleDataTableRows(dt);
          }
        },
        {
          text: 'IPs',
          action: async function (e, dt) {
            const addresses = [];

            getScopedDataTableRows(dt).forEach(row => {
              const cells = $(row).find('td');
              const address = ($(cells.get(4)).text() || '').trim();

              if (address && address.toLowerCase() !== 'n/a') {
                addresses.push(address);
              }
            });

            const uniqueAddresses = [...new Set(addresses)]
              .sort((left, right) => left.localeCompare(right, undefined, {
                numeric: true,
                sensitivity: 'base'
              }));

            await copyTextWithFeedback(
              uniqueAddresses.join('\n'),
              `Copied ${uniqueAddresses.length} IP${uniqueAddresses.length === 1 ? "" : "s"}`
            );
          }
        },
        {
          text: 'Hostnames',
          action: async function (e, dt) {
            const hostnames = [];

            getScopedDataTableRows(dt).forEach(row => {
              const cells = $(row).find('td');
              const hostname = ($(cells.get(5)).text() || '').trim();

              if (hostname && hostname.toLowerCase() !== 'n/a') {
                hostnames.push(hostname);
              }
            });

            const uniqueHostnames = [...new Set(hostnames)]
              .sort((left, right) => left.localeCompare(right, undefined, {
                numeric: true,
                sensitivity: 'base'
              }));

            await copyTextWithFeedback(
              uniqueHostnames.join('\n'),
              `Copied ${uniqueHostnames.length} hostname${uniqueHostnames.length === 1 ? "" : "s"}`
            );
          }
        }
      ]
    });
  }

  const columnDefs = [
    { targets: [0], orderable: true }
  ];

  const tableElement = document.querySelector(selector);
  if (tableElement) {
    applyAddressSortKeys(tableElement);

    const headers = Array.from(tableElement.querySelectorAll("thead th")).map(header => ($(header).text() || '').trim());
    [
      "Port",
      "Port Hosts",
      "Count",
      "Host Count",
      "Uptime (est.)",
      "Hops",
      "Rarity",
      "TCP Ports",
      "UDP Ports"
    ].forEach(headerName => {
      const columnIndex = headers.indexOf(headerName);
      if (columnIndex !== -1) {
        columnDefs.push({ targets: [columnIndex], type: 'num' });
      }
    });

    if (selector === '#service-inventory') {
      const hostDetailsColumnIndex = headers.indexOf("Host Details");
      if (hostDetailsColumnIndex !== -1) {
        columnDefs.push({ targets: [hostDetailsColumnIndex], type: 'num' });
      }
    }

    if (selector === '#table-overview') {
      const scopeColumnIndex = Array.from(tableElement.querySelectorAll("thead th"))
        .findIndex(header => header.classList.contains("host-scope-column"));
      if (scopeColumnIndex !== -1) {
        columnDefs.push({ targets: [scopeColumnIndex], type: "num", searchable: false });
      }
    }

  }

  const table = $(selector).DataTable({
    lengthMenu: [[10, 25, 50, 100, -1], [10, 25, 50, 100, "All"]],
    order: defaultOrders[selector] || [[0, 'desc']],
    columnDefs: columnDefs,
    dom: '<"datatable-toolbar"<"datatable-toolbar-start"l><"datatable-toolbar-center"f><"datatable-toolbar-end"B>>rt<"datatable-footer"<"datatable-footer-start"ip><"datatable-footer-end">>',
    stateSave: false,
    buttons: buttons,
    fixedHeader: {
      header: true,
      headerOffset: getDataTableHeaderOffset()
    }
  });

  const wrapper = table.table().container();
  if (wrapper) {
    const searchInput = wrapper.querySelector(".dataTables_filter input, .dt-search input");
    if (searchInput) {
      const syncSearchState = () => syncDataTableSearchInputState(table, wrapper);
      searchInput.addEventListener("input", syncSearchState);
      table.on("search.dt", syncSearchState);
      syncSearchState();
    }

    initializeDataTableResetButton(table, wrapper, selector, defaultOrders[selector] || [[0, "desc"]]);
  }

  if (selector === '#table-services') {
    initializeServiceDropdownFilter(table, tableElement, {
      tableLabel: "Open Services"
    });
  }

  window.requestAnimationFrame(syncDataTableFixedHeaders);
  return table;
}

function initializeDensityToggle() {
  const body = document.body;
  const buttons = Array.from(document.querySelectorAll("[data-density]"));
  if (!body || buttons.length === 0) {
    return;
  }

  const storageKey = "nmapview-table-density";

  function syncButtons(density) {
    buttons.forEach(button => {
      const isActive = button.getAttribute("data-density") === density;
      button.classList.toggle("btn-secondary", isActive);
      button.classList.toggle("btn-outline-secondary", !isActive);
      button.setAttribute("aria-pressed", isActive ? "true" : "false");
    });
  }

  function applyDensity(density) {
    const normalized = density === "dense" ? "dense" : "comfortable";
    body.classList.remove("report-density-comfortable", "report-density-dense");
    body.classList.add(`report-density-${normalized}`);
    syncButtons(normalized);
    try {
      window.localStorage.setItem(storageKey, normalized);
    } catch (error) {
    }

    if (window.jQuery && $.fn.dataTable) {
      const tables = $.fn.dataTable.tables({ visible: true });
      if (tables && tables.length > 0) {
        new $.fn.dataTable.Api(tables).columns.adjust();
      }
      syncDataTableFixedHeaders();
    }
  }

  const savedDensity = (() => {
    try {
      return window.localStorage.getItem(storageKey);
    } catch (error) {
      return null;
    }
  })();

  applyDensity(savedDensity || "comfortable");

  buttons.forEach(button => {
    button.addEventListener("click", () => {
      applyDensity(button.getAttribute("data-density"));
    });
  });
}

function escapeRegex(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function unwrapHighlight(node) {
  const parent = node.parentNode;
  if (!parent) return;

  while (node.firstChild) {
    parent.insertBefore(node.firstChild, node);
  }
  parent.removeChild(node);
}

function clearKeywordHighlights() {
  document.querySelectorAll("mark.keyword-highlight-mark").forEach(unwrapHighlight);
}

function parseHighlightTerms(raw) {
  return [...new Set(
    (raw || "")
      .split(",")
      .map(term => term.trim())
      .filter(Boolean)
  )];
}

function normalizeHighlightWildcard(pattern) {
  let normalized = "";

  for (let index = 0; index < pattern.length; index++) {
    const character = pattern[index];
    const previousCharacter = index > 0 ? pattern[index - 1] : "";

    if (character === "*" && previousCharacter !== "\\") {
      normalized += ".*";
      continue;
    }

    normalized += character;
  }

  return normalized;
}

function isRegexHighlightTerm(term) {
  return (
    /^\/.+\/$/.test(term) ||
    /^\^/.test(term) ||
    /\$$/.test(term) ||
    /(^|[^\\])\*/.test(term) ||
    /\\[dDsSwWbB]/.test(term) ||
    /(^|[^\\])[\[\]\(\)\|\+\?\{\}]/.test(term)
  );
}

function getHighlightPatternSource(term) {
  if (!isRegexHighlightTerm(term)) {
    return escapeRegex(term);
  }

  const source = /^\/.+\/$/.test(term)
    ? term.slice(1, -1)
    : normalizeHighlightWildcard(term);

  try {
    new RegExp(source, "i");
    return source;
  } catch (error) {
    return escapeRegex(term);
  }
}

function buildHighlightRegex(rawTerms) {
  const terms = parseHighlightTerms(rawTerms);
  if (terms.length === 0) {
    return null;
  }

  const sources = terms.map(getHighlightPatternSource);
  return new RegExp(`(${sources.join("|")})`, "gi");
}

function highlightTextNode(textNode, regex) {
  const text = textNode.nodeValue;
  if (!text || !regex.test(text)) {
    regex.lastIndex = 0;
    return 0;
  }

  regex.lastIndex = 0;
  const fragment = document.createDocumentFragment();
  let lastIndex = 0;
  let matchCount = 0;
  let match;

  while ((match = regex.exec(text)) !== null) {
    const matchText = match[0];
    const matchIndex = match.index;

    if (matchIndex > lastIndex) {
      fragment.appendChild(document.createTextNode(text.slice(lastIndex, matchIndex)));
    }

    const mark = document.createElement("mark");
    mark.className = "keyword-highlight-mark";
    mark.textContent = matchText;
    fragment.appendChild(mark);
    lastIndex = matchIndex + matchText.length;
    matchCount++;
  }

  if (lastIndex < text.length) {
    fragment.appendChild(document.createTextNode(text.slice(lastIndex)));
  }

  textNode.parentNode.replaceChild(fragment, textNode);
  regex.lastIndex = 0;
  return matchCount;
}

function highlightKeywords(rawTerms) {
  clearKeywordHighlights();

  const regex = buildHighlightRegex(rawTerms);
  if (!regex) {
    return 0;
  }

  const container = document.getElementById("reportContent");
  if (!container) {
    return 0;
  }

  const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      const parent = node.parentElement;
      if (!parent) return NodeFilter.FILTER_REJECT;

      if (parent.closest(".keyword-highlight-controls")) {
        return NodeFilter.FILTER_REJECT;
      }

      const tagName = parent.tagName;
      if (["SCRIPT", "STYLE", "NOSCRIPT", "TEXTAREA", "INPUT", "MARK"].includes(tagName)) {
        return NodeFilter.FILTER_REJECT;
      }

      if (!node.nodeValue || !node.nodeValue.trim()) {
        return NodeFilter.FILTER_REJECT;
      }

      return NodeFilter.FILTER_ACCEPT;
    }
  });

  const textNodes = [];
  let currentNode;
  while ((currentNode = walker.nextNode())) {
    textNodes.push(currentNode);
  }

  let matchCount = 0;
  textNodes.forEach(node => {
    matchCount += highlightTextNode(node, regex);
  });

  if (matchCount > 0) {
    document.querySelectorAll("mark.keyword-highlight-mark").forEach(mark => {
      const hostEntry = mark.closest("details.host-entry");
      if (hostEntry) {
        hostEntry.open = true;
      }
    });

    const firstMatch = document.querySelector("mark.keyword-highlight-mark");
    if (firstMatch) {
      firstMatch.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }

  return matchCount;
}

function initializeKeywordHighlighter() {
  const input = document.getElementById("keywordHighlightInput");
  const highlightButton = document.getElementById("highlightKeywordsButton");
  const resetButton = document.getElementById("resetHighlightsButton");
  if (!input || !highlightButton || !resetButton) return;

  highlightButton.addEventListener("click", () => {
    highlightKeywords(input.value);
  });

  resetButton.addEventListener("click", () => {
    clearKeywordHighlights();
    input.focus();
  });

  input.addEventListener("keydown", event => {
    if (event.key === "Enter") {
      event.preventDefault();
      highlightKeywords(input.value);
    }
  });
}
        ]]></script>
        <script><![CDATA[
          window.addEventListener("load", finalizeReportInitialization, { once: true });
          $(document).ready(function() {
	              pinReportToSummaryView();
	              initializeNavbarToggle();
	              initializeSectionNav();
	              initializeAboutDialog();
	              initializeKeywordHighlighter();
	              initializeCpeCopy();
                initializeCertificateExpiryAlerts();
                initializeOpenServiceDetails();
                buildServiceInventoryTable();
                initializeServiceInventoryToggle();
                initializeHostScopeControls();
	              initializeHostToggle();
                updateSummaryForHostScope();
                recalculateOpenServiceMetrics();
	              initializeDataTable('#table-services');
	              initializeDataTable('#table-overview');
                const detachedServiceInventoryNestedTables = detachServiceInventoryNestedTables();
	              initializeDataTable('#service-inventory');
                restoreServiceInventoryNestedTables(detachedServiceInventoryNestedTables);
                initializeServiceInventoryNestedTables();
                initializeSlashSearchShortcut();
                initializeHostUniquenessScores();
                if (typeof window.renderMatrixVisualizations === "function") {
                  window.renderMatrixVisualizations();
                }
                initializeDensityToggle();


              $("a[href^='#onlinehosts-']").click(function(event) {
                  event.preventDefault();
                  const target = openLinkedHost(this.hash);
                  if (!target) {
                    return;
                  }
                  if (window.history && window.history.pushState) {
                    window.history.pushState(null, "", this.hash);
                  }
                  $('html,body').animate({
                      scrollTop: getReportScrollTop(target)
                  }, 500);
              });

              $(document).on("click", "a[href^='#servicevariant-']", function(event) {
                  event.preventDefault();
                  const target = openLinkedServiceVariant(this.hash);
                  if (!target) {
                    return;
                  }
                  if (window.history && window.history.pushState) {
                    window.history.pushState(null, "", this.hash);
                  }
                  $('html,body').animate({
                      scrollTop: getReportScrollTop(target)
                  }, 500);
              });
          });
        ]]></script>
  </xsl:template>

<xsl:template name="render-scanned-hosts">
          <h2 id="scannedhosts" class="fs-4 mt-5 mb-3 bg-light p-3 rounded"><span class="section-heading-title">Host Overview</span><small class="section-heading-subtitle">Review scanned hosts at a high level to understand exposure, identity, and triage priority.</small></h2>
          <xsl:variable name="recorded-hosts" select="count(/nmaprun/host)"/>
          <xsl:variable name="runstats-total-hosts" select="number(/nmaprun/runstats/hosts/@total)"/>
          <xsl:choose>
	            <xsl:when test="$recorded-hosts &gt; 0">
              <div class="host-scope-controls mb-3" id="hostScopeControls">
                <span class="host-scope-label">Host Scope</span>
                <div class="btn-group btn-group-sm" role="group" aria-label="Host scope controls">
                  <button type="button" class="btn btn-outline-secondary" id="selectVisibleHostsButton">All visible</button>
                  <button type="button" class="btn btn-outline-secondary" id="clearVisibleHostsButton">None visible</button>
                </div>
                <button type="button" class="btn btn-sm btn-primary" id="applyHostScopeButton" disabled="disabled">Apply Scope</button>
                <span class="host-scope-summary" id="hostScopeSummary">All hosts selected</span>
              </div>
	              <div class="table-responsive">
                <table id="table-overview" class="table table-striped table-hover align-middle" role="grid">
                  <thead class="table-light">
	                    <tr>
	                      <th scope="col">State</th>
	                      <th scope="col">Mac</th>
	                      <th scope="col">Vendor</th>
	                      <th scope="col">OS (est.)</th>
	                      <th scope="col">Address</th>
	                      <th scope="col">Hostname</th>
	                      <th scope="col">TCP Ports</th>
	                      <th scope="col">UDP Ports</th>
	                      <th scope="col">
	                        <span title="Estimated by Nmap from TCP timestamps; useful as context, not an exact reboot time.">Uptime (est.)</span>
	                      </th>
	                      <th scope="col">
	                        <span title="Approximate hop distance from the scanner, as reported by Nmap.">Hops</span>
	                      </th>
	                      <th scope="col">
	                        <span title="Relative rarity of this host's open services within this scan. Higher scores indicate hosts with less common service combinations.">Rarity</span>
	                      </th>
                        <th scope="col" class="host-scope-column not-export">Scope</th>
	                    </tr>
	                  </thead>
	                  <tbody>
	                    <xsl:for-each select="/nmaprun/host">
	                      <xsl:variable name="vuln-count" select="count(.//script[@id='vulners']//table[elem[@key='id']])"/>
	                      <xsl:variable name="uptime-seconds-raw" select="uptime/@seconds"/>
	                      <xsl:variable name="uptime-seconds" select="number($uptime-seconds-raw)"/>
	                      <xsl:variable name="uptime-days" select="floor($uptime-seconds div 86400)"/>
	                      <xsl:variable name="uptime-hours" select="floor(($uptime-seconds mod 86400) div 3600)"/>
	                      <xsl:variable name="uptime-minutes" select="floor(($uptime-seconds mod 3600) div 60)"/>
	                      <xsl:variable name="is-up" select="status/@state='up'"/>
	                      <xsl:variable name="hostname">
                          <xsl:call-template name="resolve-effective-hostname"/>
                        </xsl:variable>
	                      <xsl:variable name="ip" select="address[not(@addrtype='mac')][1]/@addr"/>
	                      <xsl:variable name="mac-address" select="address[@addrtype='mac']/@addr"/>
	                      <xsl:variable name="mac-vendor" select="address[@addrtype='mac']/@vendor"/>
	                      <xsl:variable name="os-name" select="os/osmatch[1]/@name"/>
	                      <xsl:variable name="has-uptime-estimate" select="status/@state='up' and (string(uptime/@lastboot) != '' or $uptime-seconds &gt; 0)"/>
	                      <tr data-state="{status/@state}" data-address="{$ip}" data-issues="{$vuln-count}">
                        <td>
                          <span class="badge text-bg-secondary">
                            <xsl:if test="status/@state='up'">
                              <xsl:attribute name="class">badge bg-success</xsl:attribute>
                            </xsl:if>
                            <xsl:value-of select="status/@state"/>
                          </span>
                        </td>
                        <td>
                          <xsl:choose>
                            <xsl:when test="string($mac-address) != ''">
                              <xsl:value-of select="$mac-address"/>
                            </xsl:when>
                            <xsl:otherwise>
                              <span class="text-muted">N/A</span>
                            </xsl:otherwise>
                          </xsl:choose>
                        </td>
                        <td>
                          <xsl:choose>
                            <xsl:when test="string($mac-vendor) != ''">
                              <xsl:value-of select="$mac-vendor"/>
                            </xsl:when>
                            <xsl:otherwise>
                              <span class="text-muted">N/A</span>
                            </xsl:otherwise>
                          </xsl:choose>
                        </td>
                        <td>
                          <xsl:choose>
                            <xsl:when test="string($os-name) != ''">
                              <xsl:value-of select="$os-name"/>
                            </xsl:when>
                            <xsl:otherwise>
                              <span class="text-muted">N/A</span>
                            </xsl:otherwise>
                          </xsl:choose>
                        </td>
                        <td><xsl:attribute name="data-order"><xsl:call-template name="render-address-sort-key"><xsl:with-param name="address" select="$ip"/></xsl:call-template></xsl:attribute><xsl:choose><xsl:when test="$is-up"><xsl:call-template name="render-onlinehosts-link"><xsl:with-param name="address" select="$ip"/></xsl:call-template></xsl:when><xsl:otherwise><xsl:value-of select="$ip"/></xsl:otherwise></xsl:choose></td>
	                        <td>
	                          <xsl:choose>
	                            <xsl:when test="string(normalize-space($hostname)) != ''">
	                              <xsl:value-of select="$hostname"/>
	                            </xsl:when>
	                            <xsl:otherwise>
	                              <span class="text-muted">N/A</span>
	                            </xsl:otherwise>
	                          </xsl:choose>
	                        </td>
	                        <td>
                          <xsl:attribute name="data-order">
                            <xsl:choose>
                              <xsl:when test="$is-up">
                                <xsl:value-of select="count(ports/port[state/@state='open' and @protocol='tcp'])"/>
                              </xsl:when>
                              <xsl:otherwise>-1</xsl:otherwise>
                            </xsl:choose>
                          </xsl:attribute>
                          <xsl:choose>
                            <xsl:when test="$is-up">
                              <xsl:value-of select="count(ports/port[state/@state='open' and @protocol='tcp'])"/>
                            </xsl:when>
                            <xsl:otherwise>
                              <span class="text-muted">N/A</span>
                            </xsl:otherwise>
                          </xsl:choose>
                        </td>
                        <td>
                          <xsl:attribute name="data-order">
                            <xsl:choose>
                              <xsl:when test="$is-up">
                                <xsl:value-of select="count(ports/port[state/@state='open' and @protocol='udp'])"/>
                              </xsl:when>
                              <xsl:otherwise>-1</xsl:otherwise>
                            </xsl:choose>
                          </xsl:attribute>
                          <xsl:choose>
                            <xsl:when test="$is-up">
                              <xsl:value-of select="count(ports/port[state/@state='open' and @protocol='udp'])"/>
                            </xsl:when>
                            <xsl:otherwise>
                              <span class="text-muted">N/A</span>
                            </xsl:otherwise>
                          </xsl:choose>
                        </td>
	                        <td>
                          <xsl:attribute name="data-order">
                            <xsl:choose>
                              <xsl:when test="$has-uptime-estimate and string($uptime-seconds-raw) != ''">
                                <xsl:value-of select="$uptime-seconds"/>
                                </xsl:when>
                                <xsl:otherwise>-1</xsl:otherwise>
                              </xsl:choose>
                            </xsl:attribute>
	                          <xsl:choose>
	                            <xsl:when test="$has-uptime-estimate">
	                              <span>
	                                <xsl:attribute name="title">
	                                  <xsl:text>Estimated by Nmap from TCP timestamps</xsl:text>
	                                  <xsl:if test="string(uptime/@lastboot) != ''">
	                                    <xsl:text>. Last boot guess: </xsl:text>
	                                    <xsl:value-of select="uptime/@lastboot"/>
	                                  </xsl:if>
	                                  <xsl:if test="string($uptime-seconds-raw) != ''">
	                                    <xsl:text>. Raw seconds: </xsl:text>
	                                    <xsl:value-of select="$uptime-seconds-raw"/>
	                                  </xsl:if>
	                                </xsl:attribute>
	                                <xsl:text>~</xsl:text>
	                                <xsl:choose>
	                                  <xsl:when test="$uptime-days &gt; 0">
	                                    <xsl:value-of select="$uptime-days"/>
	                                    <xsl:text>d</xsl:text>
	                                    <xsl:if test="$uptime-hours &gt; 0">
	                                      <xsl:text> </xsl:text>
	                                      <xsl:value-of select="$uptime-hours"/>
	                                      <xsl:text>h</xsl:text>
	                                    </xsl:if>
	                                  </xsl:when>
	                                  <xsl:when test="$uptime-hours &gt; 0">
	                                    <xsl:value-of select="$uptime-hours"/>
	                                    <xsl:text>h</xsl:text>
	                                    <xsl:if test="$uptime-minutes &gt; 0">
	                                      <xsl:text> </xsl:text>
	                                      <xsl:value-of select="$uptime-minutes"/>
	                                      <xsl:text>m</xsl:text>
	                                    </xsl:if>
	                                  </xsl:when>
	                                  <xsl:when test="$uptime-minutes &gt; 0">
	                                    <xsl:value-of select="$uptime-minutes"/>
	                                    <xsl:text>m</xsl:text>
	                                  </xsl:when>
	                                  <xsl:otherwise>&lt;1m</xsl:otherwise>
	                                </xsl:choose>
	                              </span>
	                            </xsl:when>
	                            <xsl:otherwise>
	                              <span class="text-muted">N/A</span>
	                            </xsl:otherwise>
	                          </xsl:choose>
	                        </td>
	                        <td>
                            <xsl:attribute name="data-order">
                              <xsl:choose>
                                <xsl:when test="status/@state='up' and string(distance/@value) != ''">
                                  <xsl:value-of select="number(distance/@value)"/>
                                </xsl:when>
                                <xsl:otherwise>-1</xsl:otherwise>
                              </xsl:choose>
                            </xsl:attribute>
	                          <xsl:choose>
	                            <xsl:when test="status/@state='up' and string(distance/@value) != ''">
	                              <span>
	                                <xsl:attribute name="title">Approximate hop distance from the scanner</xsl:attribute>
	                                <xsl:value-of select="distance/@value"/>
	                              </span>
	                            </xsl:when>
	                            <xsl:otherwise>
	                              <span class="text-muted">N/A</span>
	                            </xsl:otherwise>
	                          </xsl:choose>
	                        </td>
                        <td class="host-uniqueness-cell" data-order="0" data-search="0">
                          <xsl:choose>
                            <xsl:when test="$is-up">
                              <span class="text-muted">Calculating...</span>
                            </xsl:when>
                            <xsl:otherwise>
                              <span class="text-muted">N/A</span>
                            </xsl:otherwise>
                          </xsl:choose>
                        </td>
                        <td class="host-scope-cell not-export" data-order="1" data-search="Included">
                          <input type="checkbox" class="form-check-input host-scope-checkbox" data-address="{$ip}" checked="checked" aria-label="Include {$ip} in recalculation"/>
                        </td>
                      </tr>
                    </xsl:for-each>
                  </tbody>
                </table>
              </div>
              <xsl:if test="count(//host/ports/port[state/@state='open' and service/@name]) &gt; 0">
                <xsl:call-template name="render-open-ports-per-host-card"/>
              </xsl:if>
              <xsl:call-template name="render-os-distribution-card"/>
            </xsl:when>
            <xsl:when test="$runstats-total-hosts = 1">
              <xsl:variable name="scan-target-raw">
                <xsl:call-template name="extract-last-token">
                  <xsl:with-param name="text" select="/nmaprun/@args"/>
                </xsl:call-template>
              </xsl:variable>
              <xsl:variable name="scan-target">
                <xsl:choose>
                  <xsl:when test="contains($scan-target-raw, '/')">
                    <xsl:value-of select="substring-before($scan-target-raw, '/')"/>
                  </xsl:when>
                  <xsl:otherwise>
                    <xsl:value-of select="$scan-target-raw"/>
                  </xsl:otherwise>
                </xsl:choose>
              </xsl:variable>
              <div class="host-scope-controls mb-3" id="hostScopeControls">
                <span class="host-scope-label">Host Scope</span>
                <div class="btn-group btn-group-sm" role="group" aria-label="Host scope controls">
                  <button type="button" class="btn btn-outline-secondary" id="selectVisibleHostsButton">All visible</button>
                  <button type="button" class="btn btn-outline-secondary" id="clearVisibleHostsButton">None visible</button>
                </div>
                <button type="button" class="btn btn-sm btn-primary" id="applyHostScopeButton" disabled="disabled">Apply Scope</button>
                <span class="host-scope-summary" id="hostScopeSummary">All hosts selected</span>
              </div>
              <div class="table-responsive">
                <table id="table-overview" class="table table-striped table-hover align-middle" role="grid">
                  <thead class="table-light">
	                    <tr>
	                      <th scope="col">State</th>
	                      <th scope="col">Mac</th>
	                      <th scope="col">Vendor</th>
	                      <th scope="col">OS (est.)</th>
	                      <th scope="col">Address</th>
	                      <th scope="col">Hostname</th>
	                      <th scope="col">TCP Ports</th>
	                      <th scope="col">UDP Ports</th>
	                      <th scope="col">
	                        <span title="Estimated by Nmap from TCP timestamps; useful as context, not an exact reboot time.">Uptime (est.)</span>
	                      </th>
	                      <th scope="col">
	                        <span title="Approximate hop distance from the scanner, as reported by Nmap.">Hops</span>
	                      </th>
	                      <th scope="col">
	                        <span title="Relative rarity of this host's open services within this scan. Higher scores indicate hosts with less common service combinations.">Rarity</span>
	                      </th>
                        <th scope="col" class="host-scope-column not-export">Scope</th>
	                    </tr>
	                  </thead>
	                  <tbody>
                      <tr data-state="down" data-address="{$scan-target}" data-issues="0">
                        <td>
                          <span class="badge text-bg-secondary">down</span>
                        </td>
                        <td data-order="-1">
                          <span class="text-muted">N/A</span>
                        </td>
                        <td data-order="-1">
                          <span class="text-muted">N/A</span>
                        </td>
                        <td data-order="-1">
                          <span class="text-muted">N/A</span>
                        </td>
                        <td>
                          <xsl:attribute name="data-order">
                            <xsl:call-template name="render-address-sort-key">
                              <xsl:with-param name="address" select="$scan-target"/>
                            </xsl:call-template>
                          </xsl:attribute>
                          <xsl:choose>
                            <xsl:when test="string($scan-target) != ''">
                              <xsl:value-of select="$scan-target"/>
                            </xsl:when>
                            <xsl:otherwise>
                              <span class="text-muted">N/A</span>
                            </xsl:otherwise>
                          </xsl:choose>
                        </td>
                        <td data-order="-1">
                          <span class="text-muted">N/A</span>
                        </td>
                        <td data-order="-1">
                          <span class="text-muted">N/A</span>
                        </td>
                        <td data-order="-1">
                          <span class="text-muted">N/A</span>
                        </td>
                        <td data-order="-1">
                          <span class="text-muted">N/A</span>
                        </td>
                        <td data-order="-1">
                          <span class="text-muted">N/A</span>
                        </td>
                        <td class="host-uniqueness-cell" data-order="-1" data-search="N/A">
                          <span class="text-muted">N/A</span>
                        </td>
                        <td class="host-scope-cell not-export" data-order="1" data-search="Included">
                          <input type="checkbox" class="form-check-input host-scope-checkbox" data-address="{$scan-target}" checked="checked" aria-label="Include {$scan-target} in recalculation"/>
                        </td>
                      </tr>
                    </tbody>
                </table>
              </div>
            </xsl:when>
            <xsl:otherwise>
              <xsl:call-template name="render-empty-state">
                <xsl:with-param name="message" select="'No hosts were recorded in this scan.'"/>
              </xsl:call-template>
            </xsl:otherwise>
          </xsl:choose>
  </xsl:template>
  <xsl:template name="render-online-hosts">
          <hr class="my-4"/>
          <h2 id="onlinehosts" class="fs-4 mt-5 mb-3 bg-light p-3 rounded"><span class="section-heading-title">Host Details</span><small class="section-heading-subtitle">Inspect each host in detail.</small></h2>
          <xsl:choose>
            <xsl:when test="count(/nmaprun/host[status/@state='up']) &gt; 0">
              <div class="host-controls mb-3">
                <button type="button" class="btn btn-outline-secondary btn-sm" id="toggle-all-hosts" aria-controls="onlinehosts-list" aria-expanded="false" title="Expand all visible host details">Toggle all</button>
              </div>
              <div class="host-list" id="onlinehosts-list">
                <xsl:for-each select="/nmaprun/host[status/@state='up']">
                  <xsl:variable name="host-id" select="translate(address/@addr, '.:', '--')"/>
                  <xsl:variable name="effective-hostname">
                    <xsl:call-template name="resolve-effective-hostname"/>
                  </xsl:variable>
                  <xsl:variable name="effective-hostname-source">
                    <xsl:call-template name="resolve-effective-hostname-source"/>
                  </xsl:variable>
                  <details class="host-entry" data-address="{address[not(@addrtype='mac')][1]/@addr}">
                    <xsl:attribute name="id">host-entry-<xsl:value-of select="$host-id"/></xsl:attribute>
                    <summary class="host-entry-summary">
                      <span class="host-entry-anchor">
                        <xsl:attribute name="id">onlinehosts-<xsl:value-of select="$host-id"/></xsl:attribute>
                      </span>
                      <span class="host-entry-label">
                        <xsl:call-template name="render-host-header-label">
                          <xsl:with-param name="address" select="address/@addr"/>
                          <xsl:with-param name="mac" select="address[@addrtype='mac']/@addr"/>
                          <xsl:with-param name="vendor" select="address[@addrtype='mac']/@vendor"/>
                          <xsl:with-param name="hostname" select="$effective-hostname"/>
                        </xsl:call-template>
                      </span>
                    </summary>
                    <div class="host-entry-body">
                    <xsl:choose>
                    <xsl:when test="count(hostnames/hostname) &gt; 0">
                      <h4 class="fs-6">Hostnames</h4>
                      <ul>
                        <xsl:for-each select="hostnames/hostname">
                          <li><xsl:value-of select="@name"/> (<xsl:value-of select="@type"/>)
                          </li>
                        </xsl:for-each>
                      </ul>
                    </xsl:when>
                    <xsl:when test="string(normalize-space($effective-hostname)) != ''">
                      <h4 class="fs-6">Hostnames</h4>
                      <ul>
                        <li><xsl:value-of select="$effective-hostname"/> (<xsl:value-of select="$effective-hostname-source"/>)</li>
                      </ul>
                    </xsl:when>
                    </xsl:choose>
                    <h4 class="fs-6">Ports</h4>
                    <div class="table-responsive">
                      <table class="table table-striped table-bordered align-middle">
                        <thead>
                          <tr class="table-light">
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>State</th>
                            <th>Reason</th>
                            <th>Service</th>
                            <th>Product</th>
                            <th>Version</th>
                            <th>Extra Info</th>
                            <th>CPE</th>
                            <th>Scripts</th>
                          </tr>
                        </thead>
                        <tbody>
                          <xsl:for-each select="ports/port">
                            <tr>
                              <td>
                                <xsl:call-template name="render-endpoint-link">
                                  <xsl:with-param name="address" select="ancestor::host[1]/address[not(@addrtype='mac')][1]/@addr"/>
                                  <xsl:with-param name="port" select="@portid"/>
                                  <xsl:with-param name="protocol" select="@protocol"/>
                                  <xsl:with-param name="service-name" select="service/@name"/>
                                  <xsl:with-param name="tunnel" select="service/@tunnel"/>
                                  <xsl:with-param name="text" select="@portid"/>
                                </xsl:call-template>
                              </td>
                              <td>
                                <xsl:value-of select="@protocol"/>
                              </td>
                              <td>
                                <xsl:value-of select="state/@state"/>
                              </td>
                              <td>
                                <xsl:value-of select="state/@reason"/>
                              </td>
                              <td>
                                <xsl:call-template name="render-service-name"/>
                              </td>
                              <td>
                                <xsl:value-of select="service/@product"/>
                              </td>
                              <td>
                                <xsl:value-of select="service/@version"/>
                              </td>
                              <td>
                                <xsl:value-of select="service/@extrainfo"/>
                              </td>
                              <td>
                                <xsl:if test="count(service/cpe) &gt; 0">
                                  <xsl:call-template name="render-nvd-cpe-link">
                                    <xsl:with-param name="cpe" select="service/cpe"/>
                                  </xsl:call-template>
                                </xsl:if>
                              </td>
                              <td>
                                <xsl:call-template name="render-script-output-list"/>
                              </td>
                            </tr>
                          </xsl:for-each>
                        </tbody>
                      </table>
                    </div>
                    <xsl:if test="count(os/osmatch) &gt; 0">
                      <h4 class="fs-6 mt-4">Operating System Detection</h4>
                      <xsl:for-each select="os/osmatch[not(@accuracy &lt; ../osmatch/@accuracy)]">
                        <h5>
                          OS Details:
                          <xsl:value-of select="@name"/>
                          (<xsl:value-of select="@accuracy"/>%)
                        </h5>
                        <xsl:for-each select="osclass">
                          <p><strong>Device Type:</strong><xsl:text> </xsl:text><xsl:value-of select="@type"/><br/><strong>Running:</strong><xsl:text> </xsl:text><xsl:value-of select="normalize-space(concat(@vendor, ' ', @osfamily, ' ', @osgen))"/>
                            <xsl:text> (</xsl:text><xsl:value-of select="@accuracy"/><xsl:text>%)</xsl:text><br/>
                            <strong>OS CPE:</strong>
                            <xsl:text> </xsl:text><xsl:if test="count(cpe) &gt; 0"><xsl:call-template name="render-nvd-cpe-link"><xsl:with-param name="cpe" select="cpe"/></xsl:call-template></xsl:if>
                          </p>
                        </xsl:for-each>
                      </xsl:for-each>
                    </xsl:if>
                    </div>
                  </details>
                </xsl:for-each>
              </div>
            </xsl:when>
            <xsl:otherwise>
              <xsl:call-template name="render-empty-state">
                <xsl:with-param name="message" select="'No hosts are marked as up in this scan.'"/>
              </xsl:call-template>
            </xsl:otherwise>
          </xsl:choose>
  </xsl:template>

<xsl:template name="render-open-services">
          <hr class="my-4"/>
          <h2 id="openservices" class="fs-4 mt-5 mb-3 bg-light p-3 rounded"><span class="section-heading-title">Open Services</span><small class="section-heading-subtitle">Pivot by exposed endpoint to see which services are reachable, where they run, and what software they appear to be.</small></h2>
          <xsl:choose>
            <xsl:when test="count(/nmaprun/host/ports/port[state/@state='open']) &gt; 0">
              <div class="table-responsive">
                <table id="table-services" class="table table-striped table-hover align-middle" role="grid">
                  <thead class="table-light">
                    <tr>
                      <th scope="col">Hostname</th>
                      <th scope="col">Address</th>
                      <th scope="col">Port</th>
                      <th scope="col">Protocol</th>
                      <th scope="col">
                        <span title="Unique hosts exposing this exact service/port combination within the current host scope. Lower values are rarer.">Count</span>
                      </th>
                      <th scope="col">Service</th>
                      <th scope="col">Product</th>
                      <th scope="col">Version</th>
                      <th scope="col">Extra Info</th>
                      <th scope="col">CPE</th>
                      <th scope="col">Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    <xsl:for-each select="/nmaprun/host">
                      <xsl:for-each select="ports/port[state/@state='open']">
                        <xsl:variable name="hostname">
                          <xsl:call-template name="resolve-effective-hostname"/>
                        </xsl:variable>
                        <xsl:variable name="ip" select="../../address[not(@addrtype='mac')][1]/@addr"/>
                        <xsl:variable name="port-id" select="@portid"/>
                        <xsl:variable name="port-protocol" select="@protocol"/>
                        <xsl:variable name="port-host-count" select="count(/nmaprun/host[ports/port[state/@state='open' and @portid=$port-id and @protocol=$port-protocol]])"/>
                        <xsl:variable name="http-headers-output" select="script[@id='http-headers']/@output"/>
                        <xsl:variable name="http-fingerprint-output" select="script[@id='fingerprint-strings']/elem[@key='GetRequest']"/>
                        <xsl:variable name="http-title">
                          <xsl:choose>
                            <xsl:when test="count(script[@id='http-title']/elem[@key='title']) &gt; 0">
                              <xsl:value-of select="script[@id='http-title']/elem[@key='title']"/>
                            </xsl:when>
                            <xsl:otherwise>
                              <xsl:value-of select="script[@id='http-title']/@output"/>
                            </xsl:otherwise>
                          </xsl:choose>
                        </xsl:variable>
                        <xsl:variable name="http-location">
                          <xsl:choose>
                            <xsl:when test="count(script[@id='http-title']/elem[@key='redirect_url']) &gt; 0">
                              <xsl:value-of select="script[@id='http-title']/elem[@key='redirect_url']"/>
                            </xsl:when>
                            <xsl:when test="contains($http-headers-output, 'Location:')">
                              <xsl:call-template name="extract-header-value">
                                <xsl:with-param name="text" select="$http-headers-output"/>
                                <xsl:with-param name="label" select="'Location'"/>
                              </xsl:call-template>
                            </xsl:when>
                            <xsl:otherwise>
                              <xsl:call-template name="extract-header-value">
                                <xsl:with-param name="text" select="$http-fingerprint-output"/>
                                <xsl:with-param name="label" select="'Location'"/>
                              </xsl:call-template>
                            </xsl:otherwise>
                          </xsl:choose>
                        </xsl:variable>
                        <xsl:variable name="http-server">
                          <xsl:choose>
                            <xsl:when test="count(script[@id='http-server-header']/elem) &gt; 0">
                              <xsl:value-of select="script[@id='http-server-header']/elem[1]"/>
                            </xsl:when>
                            <xsl:when test="string(script[@id='http-server-header']/@output) != ''">
                              <xsl:value-of select="script[@id='http-server-header']/@output"/>
                            </xsl:when>
                            <xsl:when test="contains($http-headers-output, 'Server:')">
                              <xsl:call-template name="extract-header-value">
                                <xsl:with-param name="text" select="$http-headers-output"/>
                                <xsl:with-param name="label" select="'Server'"/>
                              </xsl:call-template>
                            </xsl:when>
                            <xsl:otherwise>
                              <xsl:call-template name="extract-header-value">
                                <xsl:with-param name="text" select="$http-fingerprint-output"/>
                                <xsl:with-param name="label" select="'Server'"/>
                              </xsl:call-template>
                            </xsl:otherwise>
                          </xsl:choose>
                        </xsl:variable>
                        <xsl:variable name="http-powered-by">
                          <xsl:choose>
                            <xsl:when test="contains(translate($http-headers-output, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'powered-by:')">
                              <xsl:call-template name="extract-powered-by-value">
                                <xsl:with-param name="text" select="$http-headers-output"/>
                              </xsl:call-template>
                            </xsl:when>
                            <xsl:otherwise>
                              <xsl:call-template name="extract-powered-by-value">
                                <xsl:with-param name="text" select="$http-fingerprint-output"/>
                              </xsl:call-template>
                            </xsl:otherwise>
                          </xsl:choose>
                        </xsl:variable>
                        <xsl:variable name="http-stack-source" select="concat($http-headers-output, '&#xA;', $http-fingerprint-output)"/>
                        <xsl:variable name="http-stack-hint">
                          <xsl:call-template name="extract-stack-hint-line">
                            <xsl:with-param name="text" select="$http-stack-source"/>
                          </xsl:call-template>
                        </xsl:variable>
                        <xsl:variable name="http-powered-by-evidence">
                          <xsl:choose>
                            <xsl:when test="string($http-powered-by) != ''">
                              <xsl:value-of select="$http-powered-by"/>
                            </xsl:when>
                            <xsl:otherwise>
                              <xsl:value-of select="$http-stack-hint"/>
                            </xsl:otherwise>
                          </xsl:choose>
                        </xsl:variable>
                        <xsl:variable name="http-powered-by-stack">
                          <xsl:call-template name="normalize-powered-by-stack">
                            <xsl:with-param name="value" select="$http-stack-source"/>
                          </xsl:call-template>
                        </xsl:variable>
                        <xsl:variable name="raw-vulners-output" select=".//script[@id='vulners']/@output"/>
                        <xsl:variable name="has-http-summary"
                          select="starts-with(service/@name, 'http') or script[@id='ssl-cert'] or string($http-title) != '' or string($http-location) != '' or string($http-server) != '' or string($http-powered-by-stack) != '' or string($http-powered-by-evidence) != ''"/>
                        <xsl:variable name="has-script-details"
                          select="count(script[string(@output) != '' and not(contains(@output, 'ERROR: '))]) &gt; 0"/>
                        <tr data-address="{$ip}" data-portid="{$port-id}" data-protocol="{$port-protocol}" data-service="{service/@name}">
                          <td>
                            <xsl:call-template name="render-hostname-or-na">
                              <xsl:with-param name="hostname" select="$hostname"/>
                            </xsl:call-template>
                          </td>
                          <td><xsl:call-template name="render-onlinehosts-link"><xsl:with-param name="address" select="$ip"/></xsl:call-template></td>
                          <td>
                            <xsl:attribute name="data-order">
                              <xsl:value-of select="@portid"/>
                            </xsl:attribute>
                            <xsl:attribute name="data-search">
                              <xsl:value-of select="@portid"/>
                            </xsl:attribute>
                            <xsl:call-template name="render-endpoint-link">
                              <xsl:with-param name="address" select="$ip"/>
                              <xsl:with-param name="port" select="@portid"/>
                              <xsl:with-param name="protocol" select="@protocol"/>
                              <xsl:with-param name="service-name" select="service/@name"/>
                              <xsl:with-param name="tunnel" select="service/@tunnel"/>
                              <xsl:with-param name="text" select="@portid"/>
                            </xsl:call-template>
                          </td>
                          <td>
                            <xsl:value-of select="@protocol"/>
                          </td>
                          <td>
                            <xsl:attribute name="data-order">
                              <xsl:value-of select="$port-host-count"/>
                            </xsl:attribute>
                            <xsl:value-of select="$port-host-count"/>
                          </td>
                          <td>
                            <xsl:call-template name="render-service-name"/>
                          </td>
                          <td>
                            <xsl:value-of select="service/@product"/>
                          </td>
                          <td>
                            <xsl:value-of select="service/@version"/>
                          </td>
                          <td>
                            <xsl:value-of select="service/@extrainfo"/>
                          </td>
                          <td>
                            <xsl:call-template name="render-cpe-text">
                              <xsl:with-param name="cpe" select="service/cpe"/>
                            </xsl:call-template>
                          </td>
                          <td class="open-service-details-cell">
                            <xsl:if test="$has-http-summary or string($raw-vulners-output) != '' or $has-script-details">
                              <div class="open-service-detail-source d-none"
                                   data-address="{$ip}"
                                   data-port="{$port-id}"
                                   data-protocol="{$port-protocol}"
                                   data-http-title="{$http-title}"
                                   data-http-location="{$http-location}"
                                   data-http-server="{$http-server}"
                                   data-http-stack="{$http-powered-by-stack}"
                                   data-http-powered-by="{$http-powered-by-evidence}"
                                   data-vulners="{$raw-vulners-output}">
                                <xsl:for-each select="script[string(@output) != '' and not(contains(@output, 'ERROR: '))]">
                                  <span class="open-service-script">
                                    <xsl:attribute name="data-id">
                                      <xsl:value-of select="@id"/>
                                    </xsl:attribute>
                                    <xsl:attribute name="data-port">
                                      <xsl:value-of select="../@portid"/>
                                    </xsl:attribute>
                                    <xsl:attribute name="data-protocol">
                                      <xsl:value-of select="../@protocol"/>
                                    </xsl:attribute>
                                    <xsl:attribute name="data-valid-from">
                                      <xsl:value-of select="table[@key='validity']/elem[@key='notBefore']"/>
                                    </xsl:attribute>
                                    <xsl:attribute name="data-valid-to">
                                      <xsl:value-of select="table[@key='validity']/elem[@key='notAfter']"/>
                                    </xsl:attribute>
                                    <xsl:attribute name="data-self-signed">
                                      <xsl:choose>
                                        <xsl:when test="@id = 'ssl-cert' and normalize-space(concat(table[@key='subject']/elem[@key='commonName'], '|', table[@key='subject']/elem[@key='organizationName'])) != '' and normalize-space(concat(table[@key='subject']/elem[@key='commonName'], '|', table[@key='subject']/elem[@key='organizationName'])) = normalize-space(concat(table[@key='issuer']/elem[@key='commonName'], '|', table[@key='issuer']/elem[@key='organizationName']))">true</xsl:when>
                                        <xsl:otherwise>false</xsl:otherwise>
                                      </xsl:choose>
                                    </xsl:attribute>
                                    <xsl:value-of select="@output"/>
                                  </span>
                                </xsl:for-each>
                              </div>
                            </xsl:if>
                          </td>
                        </tr>
                      </xsl:for-each>
                    </xsl:for-each>
                  </tbody>
                </table>
              </div>
              <xsl:call-template name="render-service-distribution"/>
            </xsl:when>
            <xsl:otherwise>
              <xsl:call-template name="render-empty-state">
                <xsl:with-param name="message" select="'No open services were found in this scan.'"/>
              </xsl:call-template>
            </xsl:otherwise>
          </xsl:choose>
  </xsl:template>

  <xsl:template name="render-service-counts-data">
          <div id="serviceCounts" class="d-none">
            <xsl:for-each select="//host">
              <xsl:variable name="ip" select="address[not(@addrtype='mac')][1]/@addr"/>
              <xsl:for-each select="ports/port[state/@state='open']">
                <span class="service">
                  <xsl:attribute name="data-service">
                    <xsl:choose>
                      <xsl:when test="script[@id='ssl-cert']">
                        <xsl:text>ssl/</xsl:text>
                        <xsl:choose>
                          <xsl:when test="number(service/@conf) &gt; 5">
                            <xsl:value-of select="service/@name"/>
                          </xsl:when>
                          <xsl:otherwise>unknown</xsl:otherwise>
                        </xsl:choose>
                      </xsl:when>
                      <xsl:otherwise>
                        <xsl:choose>
                          <xsl:when test="number(service/@conf) &gt; 5">
                            <xsl:value-of select="service/@name"/>
                          </xsl:when>
                          <xsl:otherwise>unknown</xsl:otherwise>
                        </xsl:choose>
                      </xsl:otherwise>
                    </xsl:choose>
                  </xsl:attribute>
                  <xsl:attribute name="data-portid">
                    <xsl:value-of select="@portid"/>
                  </xsl:attribute>
                  <xsl:attribute name="data-porto">
                    <xsl:value-of select="@protocol"/>
                  </xsl:attribute>
                  <xsl:attribute name="data-address">
                    <xsl:value-of select="$ip"/>
                  </xsl:attribute>
                </span>
              </xsl:for-each>
            </xsl:for-each>
          </div>
  </xsl:template>

  <xsl:template name="render-service-distribution">
          <xsl:choose>
            <xsl:when test="count(/nmaprun/host/ports/port[state/@state='open']) &gt; 0">
              <xsl:call-template name="render-service-counts-data"/>
              <details class="visualization-card visualization-card-collapsible my-4" data-plot-targets="serviceChart" open="open">
                <summary class="visualization-card-summary">
                  <div class="visualization-card-header">
                    <h4 class="visualization-card-title">Service Distribution Across Hosts</h4>
                    <p class="visualization-card-note">See which services are most widespread and which appear on only a few hosts. Useful for separating normal baseline services from uncommon ones.</p>
                  </div>
                </summary>
                <div class="visualization-card-body">
                  <div class="visualization-actions">
                    <button type="button" class="btn btn-sm btn-outline-secondary" data-plot-export="serviceChart">Export</button>
                  </div>
                  <div class="service-distribution-layout">
                    <div class="service-ledger-stack">
                      <section class="service-ledger-section" aria-labelledby="topServicesLedgerTitle">
                        <h5 id="topServicesLedgerTitle" class="service-ledger-title">Top 5 Common</h5>
                        <div id="topServicesLedger" role="list"></div>
                      </section>
                    </div>
                    <div class="service-distribution-chart">
                      <div id="serviceChart" style="width: 100%; height: 220px"/>
                    </div>
                    <div class="service-ledger-stack">
                      <section class="service-ledger-section" aria-labelledby="bottomServicesLedgerTitle">
                        <h5 id="bottomServicesLedgerTitle" class="service-ledger-title">Top 5 Rare</h5>
                        <div id="bottomServicesLedger" role="list"></div>
                      </section>
                    </div>
                  </div>
                </div>
              </details>
              <xsl:if test="count(//host/ports/port[state/@state='open' and service/@name]) &gt; 0">
                <xsl:call-template name="render-host-service-relationships-card"/>
              </xsl:if>
            </xsl:when>
            <xsl:otherwise/>
          </xsl:choose>
  </xsl:template>

<xsl:template name="render-service-inventory">
          <hr class="my-4"/>
          <h2 id="serviceinventory" class="fs-4 mt-5 mb-3 bg-light p-3 rounded"><span class="section-heading-title">Service Summary</span><small class="section-heading-subtitle">Compare service variants by exact detected product and version while preserving host coverage and exposed ports.</small></h2>
          <xsl:choose>
            <xsl:when test="count(//host/ports/port[state/@state='open' and service/@name]) &gt; 0">
              <div class="service-inventory-controls mb-3">
                <button type="button" class="btn btn-outline-secondary btn-sm" id="toggle-all-service-inventory" aria-controls="serviceInventoryTableBody" aria-expanded="false" title="Expand all visible service details">Toggle all</button>
              </div>
              <div class="table-responsive">
                <table id="service-inventory" class="table table-hover table-bordered align-middle dataTable" role="grid">
                  <thead class="table-light">
                    <tr>
                      <th scope="col">Host Details</th>
                    </tr>
                  </thead>
                  <tbody id="serviceInventoryTableBody"/>
                </table>
              </div>
              <div id="serviceInventoryData" class="d-none">
                <xsl:for-each select="//host/ports/port[state/@state='open' and service/@name]">
                  <xsl:variable name="effective-hostname">
                    <xsl:call-template name="resolve-effective-hostname"/>
                  </xsl:variable>
                  <xsl:variable name="http-headers-output" select="script[@id='http-headers']/@output"/>
                  <xsl:variable name="http-fingerprint-output" select="script[@id='fingerprint-strings']/elem[@key='GetRequest']"/>
                  <xsl:variable name="http-title">
                    <xsl:choose>
                      <xsl:when test="count(script[@id='http-title']/elem[@key='title']) &gt; 0">
                        <xsl:value-of select="script[@id='http-title']/elem[@key='title']"/>
                      </xsl:when>
                      <xsl:otherwise>
                        <xsl:value-of select="script[@id='http-title']/@output"/>
                      </xsl:otherwise>
                    </xsl:choose>
                  </xsl:variable>
                  <xsl:variable name="http-location">
                    <xsl:choose>
                      <xsl:when test="count(script[@id='http-title']/elem[@key='redirect_url']) &gt; 0">
                        <xsl:value-of select="script[@id='http-title']/elem[@key='redirect_url']"/>
                      </xsl:when>
                      <xsl:when test="contains($http-headers-output, 'Location:')">
                        <xsl:call-template name="extract-header-value">
                          <xsl:with-param name="text" select="$http-headers-output"/>
                          <xsl:with-param name="label" select="'Location'"/>
                        </xsl:call-template>
                      </xsl:when>
                      <xsl:otherwise>
                        <xsl:call-template name="extract-header-value">
                          <xsl:with-param name="text" select="$http-fingerprint-output"/>
                          <xsl:with-param name="label" select="'Location'"/>
                        </xsl:call-template>
                      </xsl:otherwise>
                    </xsl:choose>
                  </xsl:variable>
                  <xsl:variable name="http-server">
                    <xsl:choose>
                      <xsl:when test="count(script[@id='http-server-header']/elem) &gt; 0">
                        <xsl:value-of select="script[@id='http-server-header']/elem[1]"/>
                      </xsl:when>
                      <xsl:when test="string(script[@id='http-server-header']/@output) != ''">
                        <xsl:value-of select="script[@id='http-server-header']/@output"/>
                      </xsl:when>
                      <xsl:when test="contains($http-headers-output, 'Server:')">
                        <xsl:call-template name="extract-header-value">
                          <xsl:with-param name="text" select="$http-headers-output"/>
                          <xsl:with-param name="label" select="'Server'"/>
                        </xsl:call-template>
                      </xsl:when>
                      <xsl:otherwise>
                        <xsl:call-template name="extract-header-value">
                          <xsl:with-param name="text" select="$http-fingerprint-output"/>
                          <xsl:with-param name="label" select="'Server'"/>
                        </xsl:call-template>
                      </xsl:otherwise>
                    </xsl:choose>
                  </xsl:variable>
                  <xsl:variable name="http-powered-by">
                    <xsl:choose>
                      <xsl:when test="contains(translate($http-headers-output, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'powered-by:')">
                        <xsl:call-template name="extract-powered-by-value">
                          <xsl:with-param name="text" select="$http-headers-output"/>
                        </xsl:call-template>
                      </xsl:when>
                      <xsl:otherwise>
                        <xsl:call-template name="extract-powered-by-value">
                          <xsl:with-param name="text" select="$http-fingerprint-output"/>
                        </xsl:call-template>
                      </xsl:otherwise>
                    </xsl:choose>
                  </xsl:variable>
                  <xsl:variable name="http-stack-source" select="concat($http-headers-output, '&#xA;', $http-fingerprint-output)"/>
                  <xsl:variable name="http-stack-hint">
                    <xsl:call-template name="extract-stack-hint-line">
                      <xsl:with-param name="text" select="$http-stack-source"/>
                    </xsl:call-template>
                  </xsl:variable>
                  <xsl:variable name="http-powered-by-evidence">
                    <xsl:choose>
                      <xsl:when test="string($http-powered-by) != ''">
                        <xsl:value-of select="$http-powered-by"/>
                      </xsl:when>
                      <xsl:otherwise>
                        <xsl:value-of select="$http-stack-hint"/>
                      </xsl:otherwise>
                    </xsl:choose>
                  </xsl:variable>
                  <xsl:variable name="http-powered-by-stack">
                    <xsl:call-template name="normalize-powered-by-stack">
                      <xsl:with-param name="value" select="$http-stack-source"/>
                    </xsl:call-template>
                  </xsl:variable>
                  <span class="service-inventory-entry">
                    <xsl:attribute name="data-service">
                      <xsl:call-template name="render-service-name"/>
                    </xsl:attribute>
                    <xsl:attribute name="data-product">
                      <xsl:value-of select="service/@product"/>
                    </xsl:attribute>
                    <xsl:attribute name="data-version">
                      <xsl:value-of select="service/@version"/>
                    </xsl:attribute>
                    <xsl:attribute name="data-extra-info">
                      <xsl:value-of select="service/@extrainfo"/>
                    </xsl:attribute>
                    <xsl:attribute name="data-address">
                      <xsl:value-of select="ancestor::host[1]/address[not(@addrtype='mac')][1]/@addr"/>
                    </xsl:attribute>
                    <xsl:attribute name="data-hostname">
                      <xsl:value-of select="$effective-hostname"/>
                    </xsl:attribute>
                    <xsl:attribute name="data-port">
                      <xsl:value-of select="@portid"/>
                    </xsl:attribute>
                    <xsl:attribute name="data-protocol">
                      <xsl:value-of select="@protocol"/>
                    </xsl:attribute>
                    <xsl:attribute name="data-http-title">
                      <xsl:value-of select="$http-title"/>
                    </xsl:attribute>
                    <xsl:attribute name="data-http-location">
                      <xsl:value-of select="$http-location"/>
                    </xsl:attribute>
                    <xsl:attribute name="data-http-server">
                      <xsl:value-of select="$http-server"/>
                    </xsl:attribute>
                    <xsl:attribute name="data-http-stack">
                      <xsl:value-of select="$http-powered-by-stack"/>
                    </xsl:attribute>
                    <xsl:attribute name="data-http-powered-by">
                      <xsl:value-of select="$http-powered-by-evidence"/>
                    </xsl:attribute>
                    <xsl:attribute name="data-vulners">
                      <xsl:value-of select=".//script[@id='vulners']/@output"/>
                    </xsl:attribute>
                    <xsl:for-each select="script[string(@output) != '' and not(contains(@output, 'ERROR: '))]">
                      <span class="service-inventory-script">
                        <xsl:attribute name="data-id">
                          <xsl:value-of select="@id"/>
                        </xsl:attribute>
                        <xsl:attribute name="data-port">
                          <xsl:value-of select="../@portid"/>
                        </xsl:attribute>
                        <xsl:attribute name="data-protocol">
                          <xsl:value-of select="../@protocol"/>
                        </xsl:attribute>
                        <xsl:attribute name="data-valid-from">
                          <xsl:value-of select="table[@key='validity']/elem[@key='notBefore']"/>
                        </xsl:attribute>
                        <xsl:attribute name="data-valid-to">
                          <xsl:value-of select="table[@key='validity']/elem[@key='notAfter']"/>
                        </xsl:attribute>
                        <xsl:attribute name="data-self-signed">
                          <xsl:choose>
                            <xsl:when test="@id = 'ssl-cert' and normalize-space(concat(table[@key='subject']/elem[@key='commonName'], '|', table[@key='subject']/elem[@key='organizationName'])) != '' and normalize-space(concat(table[@key='subject']/elem[@key='commonName'], '|', table[@key='subject']/elem[@key='organizationName'])) = normalize-space(concat(table[@key='issuer']/elem[@key='commonName'], '|', table[@key='issuer']/elem[@key='organizationName']))">true</xsl:when>
                            <xsl:otherwise>false</xsl:otherwise>
                          </xsl:choose>
                        </xsl:attribute>
                        <xsl:value-of select="@output"/>
                      </span>
                    </xsl:for-each>
                  </span>
                </xsl:for-each>
              </div>
              <xsl:call-template name="render-service-matrix-data"/>
              <xsl:call-template name="render-host-port-matrix-card"/>
              <xsl:call-template name="render-service-port-heatmap-card"/>
            </xsl:when>
            <xsl:otherwise>
              <xsl:call-template name="render-empty-state">
                <xsl:with-param name="message" select="'No named open services are available for inventory views.'"/>
              </xsl:call-template>
            </xsl:otherwise>
          </xsl:choose>
  </xsl:template>

<xsl:template name="render-visualization-head-assets">
        <script src="https://cdn.plot.ly/plotly-3.3.0.min.js" crossorigin="anonymous"></script>
  </xsl:template>

  <xsl:template name="render-visualization-styles">
        <style><![CDATA[
#topServicesLedger,
#bottomServicesLedger {
  display: block;
  max-width: 100%;
  margin: 0;
  padding: 0.7rem 0.85rem;
  border-radius: 0.85rem;
  background: var(--report-surface);
  border: 1px solid var(--report-border);
  font-family: Arial, sans-serif;
  line-height: 1.45;
}

.service-ledger-item {
  display: inline;
  padding: 0;
  font-size: 0.92rem;
  line-height: 1.2;
}

.service-ledger-name {
  font-weight: 700;
  color: #212529;
  white-space: nowrap;
}

.service-ledger-separator {
  display: inline-block;
  margin: 0 0.2rem;
  color: #6c757d;
  font-weight: 700;
  line-height: 1;
  vertical-align: middle;
}

.service-ledger-item .badge {
  display: inline-block;
  margin-left: 0.4rem;
  background-color: #007bff;
  color: white;
  padding: 0.18rem 0.48rem;
  border-radius: 999px;
  font-size: 0.72rem;
  line-height: 1.1;
  vertical-align: baseline;
}

.service-ledger-item a.badge {
  text-decoration: none;
  cursor: pointer;
}

.service-distribution-layout {
  display: grid;
  grid-template-columns: 1fr;
  gap: 0.7rem;
  align-items: start;
}

.service-distribution-chart {
  display: flex;
  justify-content: center;
  min-width: 0;
}

.service-distribution-chart > #serviceChart {
  max-width: 100%;
}

.service-ledger-stack {
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  align-items: flex-start;
  gap: 0.6rem 0.85rem;
}

.service-ledger-section {
  display: inline-grid;
  justify-items: center;
  gap: 0.55rem;
  width: fit-content;
  max-width: 100%;
}

.service-ledger-title {
  margin: 0;
  font-size: 0.92rem;
  font-weight: 700;
  color: #212529;
}

@media (max-width: 992px) {
  .service-ledger-stack {
    flex-direction: column;
    align-items: center;
  }
}

.visualization-grid {
  display: grid;
  gap: 1.1rem;
}

.visualization-card {
  border: 1px solid var(--report-border);
  border-radius: 0.9rem;
  background: var(--report-surface);
  box-shadow: var(--report-shadow);
  overflow: hidden;
}

.visualization-card-collapsible {
  overflow: hidden;
}

.visualization-card-summary {
  cursor: pointer;
  background: var(--report-surface);
  display: list-item;
  padding: 1rem 1.1rem;
  list-style-position: inside;
}

.visualization-card-summary::marker {
  color: #3f5f74;
  font-size: 1rem;
}

.visualization-card-summary::-webkit-details-marker {
  color: #3f5f74;
}

.visualization-card-summary .visualization-card-header {
  padding: 0;
  display: inline-block;
  vertical-align: top;
  width: calc(100% - 1.4rem);
  transform: translateY(0.08rem);
}

.visualization-card-collapsible[open] .visualization-card-summary {
  border-bottom: 1px solid var(--report-border);
}

.visualization-card-header {
  padding: 1rem 1.1rem 0;
}

.visualization-card-title {
  margin: 0;
  font-size: 0.98rem;
  font-weight: 700;
  color: #212529;
}

.visualization-card-note {
  margin: 0.35rem 0 0;
  color: #6c757d;
  font-size: 0.92rem;
}

.visualization-controls {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.85rem;
  margin-top: 0.85rem;
}

.visualization-control-group {
  display: inline-flex;
  align-items: center;
  gap: 0.75rem;
  min-width: min(100%, 26rem);
}

.visualization-control-label {
  font-size: 0.84rem;
  font-weight: 600;
  color: #495057;
  white-space: nowrap;
}

.visualization-control-group input[type="range"] {
  flex: 1 1 auto;
}

.visualization-control-value {
  min-width: 7rem;
  font-size: 0.84rem;
  color: #6c757d;
  text-align: right;
  white-space: nowrap;
}

.visualization-card-body {
  padding: 0.75rem 0.9rem 1rem;
}

.visualization-scroll-x {
  overflow-x: auto;
  overflow-y: hidden;
  padding-bottom: 0.2rem;
  -webkit-overflow-scrolling: touch;
}

.visualization-scroll-x > div {
  min-width: max-content;
}

.visualization-scroll-note {
  margin: 0 0 0.55rem;
  color: #6c757d;
  font-size: 0.84rem;
}

.visualization-actions {
  display: flex;
  justify-content: flex-end;
  margin-bottom: 0.55rem;
}

.visualization-actions-split {
  justify-content: space-between;
  align-items: center;
  gap: 0.75rem;
  flex-wrap: wrap;
}

.visualization-actions-split .form-check {
  margin-right: auto;
}

.visualization-empty {
  margin-top: 1rem;
}
        ]]></style>
  </xsl:template>

  <xsl:template name="render-visualizations">
          <hr class="my-4"/>
          <h2 id="visualizations" class="fs-4 mt-5 mb-3 bg-light p-3 rounded">Visualizations</h2>
          <xsl:choose>
            <xsl:when test="count(/nmaprun/host) &gt; 0">
              <p class="text-muted fst-italic mb-3 visualization-empty">Visualization plots are embedded above in Host Overview, Open Services, and Service Summary.</p>
            </xsl:when>
            <xsl:otherwise>
              <xsl:call-template name="render-empty-state">
                <xsl:with-param name="message" select="'No hosts are available for visualization plots.'"/>
              </xsl:call-template>
            </xsl:otherwise>
          </xsl:choose>
  </xsl:template>

  <xsl:template name="render-os-distribution-card">
          <details class="visualization-card visualization-card-collapsible my-4" data-plot-targets="osTreemap">
            <summary class="visualization-card-summary">
              <div class="visualization-card-header">
                <h4 class="visualization-card-title">Operating System Distribution</h4>
                <p class="visualization-card-note">See which OS families dominate the environment and where platform diversity or concentration stands out.</p>
              </div>
            </summary>
            <div class="visualization-card-body">
              <div class="visualization-actions">
                <button type="button" class="btn btn-sm btn-outline-secondary" data-plot-export="osTreemap">Export</button>
              </div>
              <div id="osTreemap" style="width: 1250px; max-width: 100%; height: 420px; margin: 0 auto;"/>
            </div>
          </details>
  </xsl:template>

  <xsl:template name="render-open-ports-per-host-card">
          <details class="visualization-card visualization-card-collapsible my-4" data-plot-targets="openPortsPerHostChart" open="open">
            <summary class="visualization-card-summary">
              <div class="visualization-card-header">
                <h4 class="visualization-card-title">Open Ports Per Host</h4>
                <p class="visualization-card-note">Compare host exposure at a glance. Use it to spot high-exposure systems and hosts that combine broad surface area with unusual service profiles.</p>
              </div>
            </summary>
            <div class="visualization-card-body">
              <div class="visualization-actions">
                <button type="button" class="btn btn-sm btn-outline-secondary" data-plot-export="openPortsPerHostChart">Export</button>
              </div>
              <div class="visualization-scroll-x">
                <div id="openPortsPerHostChart" style="width: 100%;"/>
              </div>
            </div>
          </details>
  </xsl:template>

  <xsl:template name="render-host-service-relationships-card">
          <details class="visualization-card visualization-card-collapsible my-4" data-plot-targets="hostServiceGraph">
            <summary class="visualization-card-summary">
              <div class="visualization-card-header">
                <h4 class="visualization-card-title">Host-Service Relationships</h4>
                <p class="visualization-card-note">See which services are shared across hosts and which ones are isolated. Useful for spotting common baselines versus one-off systems.</p>
              </div>
            </summary>
            <div class="visualization-card-body">
              <div class="visualization-actions">
                <button type="button" class="btn btn-sm btn-outline-secondary" data-plot-export="hostServiceGraph">Export</button>
              </div>
              <div class="visualization-scroll-x">
                <div id="hostServiceGraph" style="width: 100%;"/>
              </div>
            </div>
          </details>
  </xsl:template>

  <xsl:template name="render-service-matrix-data">
          <div id="matrixCount" class="d-none">
            <xsl:for-each select="//host">
              <xsl:variable name="effective-hostname">
                <xsl:call-template name="resolve-effective-hostname"/>
              </xsl:variable>
              <xsl:variable name="ip" select="address[not(@addrtype='mac')][1]/@addr"/>
              <div class="host">
                <xsl:attribute name="data-address">
                  <xsl:value-of select="$ip"/>
                </xsl:attribute>
                <xsl:attribute name="data-host">
	                  <xsl:value-of select="$ip"/>
	                  <xsl:if test="string(normalize-space($effective-hostname)) != ''">
	                    <xsl:text> - </xsl:text>
	                    <xsl:value-of select="$effective-hostname"/>
	                  </xsl:if>
                </xsl:attribute>
                <xsl:for-each select="ports/port[state/@state='open' and service/@name]">
                  <span class="port" data-port="{@portid}" data-conf="{service/@conf}">
                    <xsl:attribute name="data-service">
                      <xsl:value-of select="@protocol"/>
                      <xsl:text>:</xsl:text>
                      <xsl:if test="service/@tunnel = 'ssl'">
                        <xsl:text>ssl/</xsl:text>
                      </xsl:if>
                      <xsl:value-of select="service/@name"/>
                    </xsl:attribute>
                    <xsl:attribute name="data-service-graph-label">
                      <xsl:if test="service/@tunnel = 'ssl'">
                        <xsl:text>ssl/</xsl:text>
                      </xsl:if>
                      <xsl:value-of select="service/@name"/>
                      <xsl:text> </xsl:text>
                      <xsl:value-of select="@portid"/>
                      <xsl:text>/</xsl:text>
                      <xsl:value-of select="@protocol"/>
                    </xsl:attribute>
                  </span>
                </xsl:for-each>
              </div>
            </xsl:for-each>
          </div>
  </xsl:template>

  <xsl:template name="render-host-port-matrix-card">
          <details class="visualization-card visualization-card-collapsible my-4" data-plot-targets="portHostMatrix" open="open">
            <summary class="visualization-card-summary">
              <div class="visualization-card-header">
                <h4 class="visualization-card-title">Host-Port Matrix</h4>
                <p class="visualization-card-note">See which ports appear on which hosts and spot unusual exposure patterns.</p>
              </div>
            </summary>
            <div class="visualization-card-body">
              <div class="visualization-actions visualization-actions-split">
                <div class="form-check form-switch mb-0">
                  <input type="checkbox" class="form-check-input" id="portHostPercentileToggle"/>
                  <label class="form-check-label small" for="portHostPercentileToggle">Mark 95th percentile uncommon ports</label>
                </div>
                <button type="button" class="btn btn-sm btn-outline-secondary" data-plot-export="portHostMatrix">Export</button>
              </div>
              <div class="visualization-scroll-x">
                <div id="portHostMatrix" style="width: 100%;"/>
              </div>
            </div>
          </details>
  </xsl:template>

  <xsl:template name="render-service-port-heatmap-card">
          <details class="visualization-card visualization-card-collapsible my-4" data-plot-targets="protocolPortMatrix">
            <summary class="visualization-card-summary">
              <div class="visualization-card-header">
                <h4 class="visualization-card-title">Service-Port Heatmap</h4>
                <p class="visualization-card-note">See which services cluster on which ports. Useful for confirming expected port usage and spotting unusual service-to-port combinations.</p>
              </div>
            </summary>
            <div class="visualization-card-body">
              <div class="visualization-actions">
                <button type="button" class="btn btn-sm btn-outline-secondary" data-plot-export="protocolPortMatrix">Export</button>
              </div>
              <div class="visualization-scroll-x">
                <div id="protocolPortMatrix" style="width: 100%;"/>
              </div>
            </div>
          </details>
  </xsl:template>

  <xsl:template name="render-visualization-scripts">
        <script><![CDATA[
function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function getDynamicTileSize(columns, rows, options = {}) {
  const maxWidth = options.maxWidth || Math.max(window.innerWidth - 220, 720);
  const maxHeight = options.maxHeight || Math.max(window.innerHeight * 0.7, 520);
  const minSize = options.minSize || 12;
  const maxSize = options.maxSize || 36;

  if (!columns || !rows) {
    return maxSize;
  }

  const widthLimited = Math.floor(maxWidth / columns);
  const heightLimited = Math.floor(maxHeight / rows);
  return clamp(Math.min(widthLimited, heightLimited), minSize, maxSize);
}

function truncateLabel(text, maxLength = 42) {
  if (!text || text.length <= maxLength) {
    return text;
  }
  return `${text.slice(0, maxLength - 1)}…`;
}

function calculatePercentile(values, percentile) {
  const numbers = (values || [])
    .map(value => Number(value))
    .filter(value => Number.isFinite(value))
    .sort((a, b) => a - b);

  if (numbers.length === 0) {
    return 0;
  }

  const clampedPercentile = clamp(Number(percentile), 0, 1);
  const index = Math.max(0, Math.min(numbers.length - 1, Math.floor((numbers.length - 1) * clampedPercentile)));
  return numbers[index];
}

function renderServiceLedger(ledgerId, services, separatorText, options = {}) {
  const ledger = document.getElementById(ledgerId);
  if (!ledger) return;
  const { hostMap = new Map(), linkSingleHost = false } = options;

  ledger.textContent = "";
  (services || []).forEach(([service, count], index) => {
    if (index > 0) {
      const separator = document.createElement("span");
      separator.className = "service-ledger-separator";
      separator.textContent = separatorText;
      ledger.appendChild(separator);
    }

    const listItem = document.createElement("div");
    const title = document.createElement("span");
    const hosts = Array.from(hostMap.get(service) || []);
    const singleHostLink = linkSingleHost && hosts.length === 1 ? hosts[0] : "";
    const badge = singleHostLink
      ? document.createElement("a")
      : document.createElement("span");

    listItem.className = "service-ledger-item";
    listItem.setAttribute("role", "listitem");
    title.className = "service-ledger-name";
    title.textContent = service;
    badge.className = "badge";
    badge.textContent = String(count);
    badge.title = singleHostLink
      ? `Jump to ${singleHostLink}`
      : `${count} host${count === 1 ? "" : "s"}`;
    if (singleHostLink) {
      badge.href = `#onlinehosts-${singleHostLink.replace(/[.:]/g, "-")}`;
    }

    listItem.appendChild(title);
    listItem.appendChild(badge);
    ledger.appendChild(listItem);
  });
}

function renderServiceLedgers(sortedServices, hostMap) {
  const topServices = sortedServices.slice(0, 5);
  const bottomServices = sortedServices.length <= 5
    ? sortedServices.slice()
    : [...sortedServices]
      .sort((a, b) => a[1] - b[1] || a[0].localeCompare(b[0], undefined, {
        numeric: true,
        sensitivity: "base"
      }))
      .slice(0, 5);

  renderServiceLedger("topServicesLedger", topServices, ">", { hostMap });
  renderServiceLedger("bottomServicesLedger", bottomServices, "<", { hostMap, linkSingleHost: true });
}

function classifyOperatingSystemFamily(name) {
  const normalized = (name || "").toLowerCase();
  if (!normalized || normalized === "unknown") return "unknown";
  if (normalized.includes("windows")) return "windows";
  if (normalized.includes("linux")) return "linux";
  if (normalized.includes("freebsd") || normalized.includes("openbsd") || normalized.includes("netbsd") || normalized.includes("bsd")) return "bsd";
  if (normalized.includes("mac os") || normalized.includes("macos") || normalized.includes("os x") || normalized.includes("darwin")) return "macos";
  if (normalized.includes("cisco") || normalized.includes("router") || normalized.includes("switch") || normalized.includes("embedded")) return "network";
  return "unknown";
}

function formatHostDetails(hostDetails) {
  const uniqueHostDetails = [...new Set((hostDetails || []).filter(Boolean))];
  if (uniqueHostDetails.length === 0) {
    return "Host details: N/A";
  }

  uniqueHostDetails.sort((a, b) => a.localeCompare(b, undefined, {
    numeric: true,
    sensitivity: "base"
  }));

  return `Host details:<br>${uniqueHostDetails.join("<br>")}`;
}

function normalizeUniquenessService(service) {
  const normalized = (service || "").trim().toLowerCase();
  if (!normalized) {
    return "";
  }

  const separatorIndex = normalized.indexOf(":");
  const protocol = separatorIndex === -1 ? "" : normalized.slice(0, separatorIndex);
  let serviceName = separatorIndex === -1 ? normalized : normalized.slice(separatorIndex + 1);

  if (!serviceName || serviceName === "unknown") {
    return "";
  }

  if (serviceName === "ssl/http" || serviceName === "ssl/https" || serviceName === "https") {
    serviceName = "https";
  }

  return protocol ? `${protocol}:${serviceName}` : serviceName;
}

function formatUniquenessServiceLabel(serviceKey) {
  const normalized = normalizeUniquenessService(serviceKey);
  if (!normalized) {
    return "unknown";
  }

  const separatorIndex = normalized.indexOf(":");
  if (separatorIndex === -1) {
    return normalized;
  }

  const protocol = normalized.slice(0, separatorIndex).toUpperCase();
  const serviceName = normalized.slice(separatorIndex + 1);
  return `${serviceName} (${protocol})`;
}

function setHostUniquenessCell(cell, options = {}) {
  if (!cell) {
    return;
  }

  const {
    score = null,
    rawScore = 0,
    contributors = [],
    isUp = false,
    hasQualifyingServices = false,
    isExcluded = false
  } = options;

  cell.textContent = "";

  if (isExcluded) {
    cell.dataset.order = "-1";
    cell.dataset.search = "Out";

    const placeholder = document.createElement("span");
    placeholder.className = "text-muted";
    placeholder.textContent = "Out";
    cell.appendChild(placeholder);
    return;
  }

  if (!isUp) {
    cell.dataset.order = "-1";
    cell.dataset.search = "N/A";

    const placeholder = document.createElement("span");
    placeholder.className = "text-muted";
    placeholder.textContent = "N/A";
    cell.appendChild(placeholder);
    return;
  }

  const normalizedScore = Number.isFinite(score) ? score : 0;
  const value = document.createElement("span");
  value.textContent = normalizedScore.toFixed(1);
  if (normalizedScore <= 0) {
    value.className = "text-muted";
  }

  if (contributors.length > 0) {
    value.title = `Relative rarity score within this scan. Raw score: ${rawScore.toFixed(2)}. Top contributors: ${contributors.join(", ")}`;
  } else if (hasQualifyingServices) {
    value.title = `Relative rarity score within this scan. Raw score: ${rawScore.toFixed(2)}. No standout services on this host.`;
  } else {
    value.title = "No qualifying named services on this host.";
  }

  cell.dataset.order = normalizedScore.toFixed(4);
  cell.dataset.search = normalizedScore.toFixed(1);
  cell.appendChild(value);
}

function getHostOverviewRows(hostOverviewTable) {
  if (!hostOverviewTable) {
    return [];
  }

  if (window.jQuery && $.fn.dataTable && $.fn.dataTable.isDataTable(hostOverviewTable)) {
    const tableApi = $(hostOverviewTable).DataTable();
    if (tableApi) {
      return tableApi.rows().nodes().toArray();
    }
  }

  return Array.from(hostOverviewTable.querySelectorAll("tbody tr"));
}

function buildHostUniquenessScoreMap(hostOverviewTable) {
  if (!hostOverviewTable) {
    return new Map();
  }

  const headers = Array.from(hostOverviewTable.querySelectorAll("thead th")).map(header => (header.textContent || "").trim());
  const addressColumnIndex = headers.indexOf("Address");
  if (addressColumnIndex === -1) {
    return new Map();
  }

  const rows = getHostOverviewRows(hostOverviewTable);
  if (rows.length === 0) {
    return new Map();
  }

  const upRows = rows.filter(row =>
    (row.dataset.state || "").trim() === "up" &&
    (!window.isHostInScope || window.isHostInScope(row.dataset.address || ""))
  );
  const totalUpHosts = upRows.length;
  const hostServices = new Map();
  const serviceFrequency = new Map();

  document.querySelectorAll("#matrixCount .host").forEach(hostElement => {
    const address = (hostElement.dataset.address || "").trim();
    if (!address || (window.isHostInScope && !window.isHostInScope(address))) {
      return;
    }

    const uniqueServices = new Map();

    hostElement.querySelectorAll(".port").forEach(portElement => {
      const confidence = Number.parseInt(portElement.dataset.conf || "", 10);
      if (Number.isFinite(confidence) && confidence <= 3) {
        return;
      }

      const serviceKey = normalizeUniquenessService(portElement.dataset.service || "");
      if (!serviceKey) {
        return;
      }

      if (!uniqueServices.has(serviceKey)) {
        uniqueServices.set(serviceKey, {
          key: serviceKey,
          label: formatUniquenessServiceLabel(serviceKey)
        });
      }
    });

    hostServices.set(address, uniqueServices);
    uniqueServices.forEach((_, serviceKey) => {
      serviceFrequency.set(serviceKey, (serviceFrequency.get(serviceKey) || 0) + 1);
    });
  });

  const hostRawScores = new Map();
  let maxRawScore = 0;

  upRows.forEach(row => {
    const cells = row.querySelectorAll("td");
    const address = (row.dataset.address || (cells.length > addressColumnIndex ? cells[addressColumnIndex].textContent : "") || "").trim();
    if (!address) {
      return;
    }
    const services = hostServices.get(address) || new Map();
    const contributors = [];
    let rawScore = 0;

    services.forEach(entry => {
      const frequency = serviceFrequency.get(entry.key) || 0;
      if (!frequency || totalUpHosts <= 1) {
        return;
      }

      const weight = Math.log2(totalUpHosts / frequency);
      if (!Number.isFinite(weight) || weight <= 0) {
        return;
      }

      rawScore += weight;
      contributors.push({
        label: entry.label,
        weight: weight
      });
    });

    contributors.sort((a, b) => b.weight - a.weight || a.label.localeCompare(b.label, undefined, {
      numeric: true,
      sensitivity: "base"
    }));

    hostRawScores.set(address, {
      rawScore,
      contributors: contributors.slice(0, 3).map(entry => `${entry.label} (${entry.weight.toFixed(2)})`),
      hasQualifyingServices: services.size > 0
    });
    maxRawScore = Math.max(maxRawScore, rawScore);
  });

  const hostScores = new Map();
  hostRawScores.forEach((scoreDetails, address) => {
    hostScores.set(address, {
      ...scoreDetails,
      score: maxRawScore > 0 ? (scoreDetails.rawScore / maxRawScore) * 100 : 0
    });
  });

  return hostScores;
}

function initializeHostUniquenessScores() {
  const hostOverviewTable = document.getElementById("table-overview");
  if (!hostOverviewTable) {
    return new Map();
  }

  const headers = Array.from(hostOverviewTable.querySelectorAll("thead th")).map(header => (header.textContent || "").trim());
  const addressColumnIndex = headers.indexOf("Address");
  const uniquenessColumnIndex = headers.indexOf("Rarity");
  if (addressColumnIndex === -1 || uniquenessColumnIndex === -1) {
    return new Map();
  }

  const rows = getHostOverviewRows(hostOverviewTable);
  if (rows.length === 0) {
    return new Map();
  }

  const hostScores = buildHostUniquenessScoreMap(hostOverviewTable);

  rows.forEach(row => {
    const cells = row.querySelectorAll("td");
    if (cells.length <= uniquenessColumnIndex) {
      return;
    }

    const cell = cells[uniquenessColumnIndex];
    const address = (row.dataset.address || (cells.length > addressColumnIndex ? cells[addressColumnIndex].textContent : "") || "").trim();
    if (address && window.isHostInScope && !window.isHostInScope(address)) {
      setHostUniquenessCell(cell, { isExcluded: true });
      return;
    }

    const isUp = (row.dataset.state || "").trim() === "up";
    if (!isUp) {
      setHostUniquenessCell(cell, { isUp: false });
      return;
    }

    const scoreDetails = hostScores.get(address) || {
      score: 0,
      rawScore: 0,
      contributors: [],
      hasQualifyingServices: false
    };

    setHostUniquenessCell(cell, {
      score: scoreDetails.score,
      rawScore: scoreDetails.rawScore,
      contributors: scoreDetails.contributors,
      isUp: true,
      hasQualifyingServices: scoreDetails.hasQualifyingServices
    });
  });

  if (window.jQuery && $.fn.dataTable && $.fn.dataTable.isDataTable(hostOverviewTable)) {
    const tableApi = $(hostOverviewTable).DataTable();
    if (tableApi) {
      tableApi.rows().invalidate("dom").draw(false);
      tableApi.columns.adjust();
      if (tableApi.fixedHeader && typeof tableApi.fixedHeader.adjust === "function") {
        tableApi.fixedHeader.adjust();
      }
    }
  }

  return hostScores;
}

function getCollapsiblePlotTargets(detailsElement) {
  return (detailsElement && detailsElement.dataset.plotTargets
    ? detailsElement.dataset.plotTargets.split(/\s+/)
    : [])
    .map(value => value.trim())
    .filter(Boolean);
}

function refreshVisualizationPlot(plotId) {
  const plotElement = document.getElementById(plotId);
  if (!plotElement || !window.Plotly || !plotElement.data) {
    return;
  }

  if (plotId === "osTreemap") {
    const parentWidth = plotElement.parentElement ? plotElement.parentElement.clientWidth : 0;
    const treemapWidth = Math.min(1250, Math.max(parentWidth || 0, 320));
    const treemapHeight = Math.max(315, Math.round(treemapWidth * 0.336));

    plotElement.style.width = `${treemapWidth}px`;
    plotElement.style.height = `${treemapHeight}px`;
    plotElement.style.margin = "0 auto";
    Plotly.relayout(plotElement, {
      width: treemapWidth,
      height: treemapHeight
    });
  } else if (plotId === "serviceChart") {
    plotElement.style.width = "100%";
    plotElement.style.margin = "0 auto";
    Plotly.relayout(plotElement, {
      autosize: true,
      height: 220
    });
  }

  Plotly.Plots.resize(plotElement);
}

function refreshCollapsibleVisualization(detailsElement) {
  getCollapsiblePlotTargets(detailsElement).forEach(refreshVisualizationPlot);
}

function getReportCssVar(name, fallback) {
  try {
    const value = window.getComputedStyle(document.documentElement).getPropertyValue(name);
    return (value || "").trim() || fallback;
  } catch (error) {
    return fallback;
  }
}

function getPlotLayoutTheme() {
  return {
    paper_bgcolor: getReportCssVar("--report-surface", "#f7f9fb"),
    plot_bgcolor: getReportCssVar("--report-surface", "#f7f9fb")
  };
}

function computeStableHashFragment(value, length = 4) {
  const normalized = String(value || "");
  let hash = 2166136261;

  for (let index = 0; index < normalized.length; index += 1) {
    hash ^= normalized.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }

  return (hash >>> 0).toString(36).padStart(length, "0").slice(0, length);
}

function getReportExportHash() {
  const body = document.body;
  if (!body) {
    return "0000";
  }

  const fingerprintSource = [
    body.dataset.reportCommand || "",
    body.dataset.reportStart || "",
    body.dataset.reportVersion || "",
    document.title || ""
  ].join("|");

  return computeStableHashFragment(fingerprintSource, 4);
}

function initializePlotExportButtons() {
  const reportExportHash = getReportExportHash();
  document.querySelectorAll("[data-plot-export]").forEach(button => {
    button.addEventListener("click", () => {
      const plotId = button.getAttribute("data-plot-export");
      const plotElement = plotId ? document.getElementById(plotId) : null;
      if (!plotElement || !window.Plotly) {
        return;
      }

      Plotly.downloadImage(plotElement, {
        format: "png",
        filename: `nmapview-${plotId}-${reportExportHash}`,
        width: plotElement.clientWidth || undefined,
        height: plotElement.clientHeight || undefined,
        scale: 2
      });
    });
  });
}
        ]]></script>
        <script><![CDATA[
function getScopedServiceCountElements() {
  return Array.from(document.querySelectorAll("#serviceCounts .service")).filter(element => {
    const address = (element.getAttribute("data-address") || "").trim();
    return !window.isHostInScope || window.isHostInScope(address);
  });
}

function renderServiceChart() {
  const serviceChart = document.getElementById("serviceChart");
  if (!serviceChart) {
    return;
  }

  const serviceCounts = {};
  const serviceHosts = new Map();

  getScopedServiceCountElements().forEach(element => {
    const service = element.getAttribute("data-service");
    const port = element.getAttribute("data-portid");
    const protocol = element.getAttribute("data-porto");
    const address = (element.getAttribute("data-address") || "").trim();

    if (!service || !port) {
      return;
    }

    const key = `${service} (${protocol}/${port})`;
    serviceCounts[key] = (serviceCounts[key] || 0) + 1;
    if (address) {
      if (!serviceHosts.has(key)) {
        serviceHosts.set(key, new Set());
      }
      serviceHosts.get(key).add(address);
    }
  });

  const sortedServices = Object.entries(serviceCounts).sort((a, b) => b[1] - a[1]);
  renderServiceLedgers(sortedServices, serviceHosts);

  if (sortedServices.length === 0) {
    if (window.Plotly) {
      Plotly.purge(serviceChart);
    }
    serviceChart.innerHTML = "";
    return;
  }

  const colorPalette = [
    "#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd",
    "#8c564b", "#e377c2", "#7f7f7f", "#bcbd22", "#17becf",
    "#393b79", "#637939", "#8c6d31", "#843c39", "#7b4173",
    "#3182bd", "#f33", "#11b", "#fb0", "#0f0", "#999", "#05a"
  ];

  const traces = sortedServices.map(([service, count], index) => ({
    y: [""],
    x: [count],
    name: service,
    type: "bar",
    orientation: "h",
    marker: {
      color: colorPalette[index % colorPalette.length]
    },
    text: service,
    hovertext: `Service: ${service}; Hosts: ${count}`,
    textposition: "inside",
    insidetextanchor: "start",
    hoverinfo: "text",
    textfont: {
      color: "white",
      size: 12
    }
  }));

  const layout = {
    title: "",
    barmode: "stack",
    height: 220,
    xaxis: {
      title: "Frequency",
      automargin: true,
      fixedrange: true,
      showticklabels: false,
      showgrid: false
    },
    yaxis: {
      automargin: true,
      fixedrange: true,
      showgrid: false
    },
    showlegend: false,
    margin: {
      t: 24,
      b: 34,
      l: 50,
      r: 30
    },
    ...getPlotLayoutTheme()
  };

  const config = {
    displayModeBar: false,
    responsive: true
  };

  if (serviceChart.data) {
    Plotly.react(serviceChart, traces, layout, config);
    return;
  }

  Plotly.newPlot(serviceChart, traces, layout, config);
}

function renderOsTreemap() {
  const hostOverviewTable = document.getElementById("table-overview");
  const osTreemap = document.getElementById("osTreemap");
  if (!hostOverviewTable || !osTreemap) {
    return;
  }

  const hostOverviewHeaders = Array.from(hostOverviewTable.querySelectorAll("thead th")).map(header => (header.textContent || "").trim());
  const osColumnIndex = hostOverviewHeaders.indexOf("OS (est.)");
  const addressColumnIndex = hostOverviewHeaders.indexOf("Address");
  const hostnameColumnIndex = hostOverviewHeaders.indexOf("Hostname");
  if (osColumnIndex === -1 || addressColumnIndex === -1 || hostnameColumnIndex === -1) {
    return;
  }

  const hostOverviewRows = (typeof window.getTableRows === "function"
    ? window.getTableRows("table-overview", { requireAddress: true })
    : Array.from(document.querySelectorAll("#table-overview tbody tr")))
    .filter(row => !window.isHostInScope || window.isHostInScope(row.dataset.address || ""));

  const osMap = new Map();
  hostOverviewRows.forEach(row => {
    const cells = row.querySelectorAll("td");
    if (cells.length <= Math.max(osColumnIndex, addressColumnIndex, hostnameColumnIndex)) {
      return;
    }

    const os = (cells[osColumnIndex].textContent || "").trim() || "Unknown";
    const address = (cells[addressColumnIndex].textContent || "").trim();
    const hostname = (cells[hostnameColumnIndex].textContent || "").trim();
    const hostLabel = address && hostname ? `${address} (${hostname})` : (address || hostname || "N/A");
    const current = osMap.get(os) || { hosts: 0, hostDetails: [] };
    current.hosts += 1;
    current.hostDetails.push(hostLabel);
    osMap.set(os, current);
  });

  const osEntries = Array.from(osMap.entries())
    .map(([os, values]) => ({ os, ...values }))
    .sort((a, b) => b.hosts - a.hosts || a.os.localeCompare(b.os, undefined, {
      numeric: true,
      sensitivity: "base"
    }));

  if (osEntries.length === 0) {
    if (window.Plotly) {
      Plotly.purge(osTreemap);
    }
    osTreemap.innerHTML = "";
    return;
  }

  const familyColorMap = {
    linux: "#0d6efd",
    windows: "#198754",
    bsd: "#fd7e14",
    macos: "#6f42c1",
    network: "#20c997",
    unknown: "#6c757d"
  };
  const familyLightColorMap = {
    linux: "#d7e7ff",
    windows: "#d6f0df",
    bsd: "#ffe5d0",
    macos: "#e2d9f3",
    network: "#d2f4ea",
    unknown: "#e9ecef"
  };
  const familyCounts = {};
  const familyHostDetails = {};
  const treemapLabels = ["Operating Systems"];
  const treemapParents = [""];
  const treemapValues = [osEntries.reduce((total, entry) => total + entry.hosts, 0)];
  const treemapCustomData = [["All OS families", String(treemapValues[0])]];
  const treemapHoverText = [];
  const treemapColors = [getReportCssVar("--report-surface-muted", "#e6ebf0")];
  const treemapWidth = Math.min(1250, osTreemap.parentElement ? osTreemap.parentElement.clientWidth : 1250);
  const treemapHeight = Math.max(315, Math.round(treemapWidth * 0.336));

  osTreemap.style.width = `${treemapWidth}px`;
  osTreemap.style.height = `${treemapHeight}px`;
  osTreemap.style.margin = "0 auto";

  osEntries.forEach(entry => {
    const family = classifyOperatingSystemFamily(entry.os);
    familyCounts[family] = (familyCounts[family] || 0) + entry.hosts;
    familyHostDetails[family] = (familyHostDetails[family] || []).concat(entry.hostDetails || []);
  });

  treemapHoverText.push(`Operating Systems<br>Hosts: ${treemapValues[0]}<br>${formatHostDetails(osEntries.flatMap(entry => entry.hostDetails || []))}`);

  Object.entries(familyCounts)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0], undefined, {
      numeric: true,
      sensitivity: "base"
    }))
    .forEach(([family, count]) => {
      treemapLabels.push(family.toUpperCase());
      treemapParents.push("Operating Systems");
      treemapValues.push(count);
      treemapCustomData.push([family, String(count)]);
      treemapHoverText.push(`${family.toUpperCase()}<br>Hosts: ${count}<br>${formatHostDetails(familyHostDetails[family])}`);
      treemapColors.push(familyColorMap[family] || familyColorMap.unknown);
    });

  osEntries.forEach(entry => {
    const family = classifyOperatingSystemFamily(entry.os);
    treemapLabels.push(entry.os);
    treemapParents.push(family.toUpperCase());
    treemapValues.push(entry.hosts);
    treemapCustomData.push([family, String(entry.hosts)]);
    treemapHoverText.push(`${entry.os}<br>Hosts: ${entry.hosts}<br>${formatHostDetails(entry.hostDetails)}`);
    treemapColors.push(familyLightColorMap[family] || familyLightColorMap.unknown);
  });

  const data = [{
    type: "treemap",
    labels: treemapLabels,
    parents: treemapParents,
    values: treemapValues,
    branchvalues: "total",
    textinfo: "label+value",
    customdata: treemapCustomData,
    hovertext: treemapHoverText,
    marker: {
      colors: treemapColors,
      line: {
        color: "#ffffff",
        width: 1
      }
    },
    tiling: {
      packing: "squarify"
    },
    hovertemplate: "%{hovertext}<extra></extra>"
  }];

  const layout = {
    title: "",
    width: treemapWidth,
    height: treemapHeight,
    margin: { t: 10, l: 10, r: 10, b: 10 },
    ...getPlotLayoutTheme()
  };

  const config = {
    displayModeBar: false,
    responsive: true
  };

  if (osTreemap.data) {
    Plotly.react(osTreemap, data, layout, config);
    return;
  }

  Plotly.newPlot(osTreemap, data, layout, config);
}

function renderServiceDistributionVisualizations() {
  if (!window.Plotly) {
    return;
  }

  renderServiceChart();
  renderOsTreemap();
}

window.renderServiceDistributionVisualizations = renderServiceDistributionVisualizations;

document.addEventListener("DOMContentLoaded", function() {
  initializePlotExportButtons();
  renderServiceDistributionVisualizations();
});
        ]]></script>
        <script><![CDATA[
function purgePlotlyElement(elementId) {
  const element = document.getElementById(elementId);
  if (!element) {
    return;
  }

  if (window.Plotly) {
    Plotly.purge(element);
  }
  element.innerHTML = "";
}

function getScopedMatrixHostDivs() {
  return Array.from(document.querySelectorAll("#matrixCount .host")).filter(hostDiv => {
    const address = (hostDiv.getAttribute("data-address") || "").trim();
    return !window.isHostInScope || window.isHostInScope(address);
  });
}

function buildScopedMatrixData() {
  const hostDivs = getScopedMatrixHostDivs();
  const hosts = [];
  const portsSet = new Set();
  const servicesSet = new Set();
  const openServices = {};

  hostDivs.forEach(hostDiv => {
    const host = hostDiv.getAttribute("data-host");
    if (!host) {
      return;
    }

    hosts.push(host);
    openServices[host] = {};

    hostDiv.querySelectorAll("span.port").forEach(span => {
      const port = parseInt(span.getAttribute("data-port"), 10);
      const serviceName = span.getAttribute("data-service") || "";
      if (!Number.isFinite(port)) {
        return;
      }

      openServices[host][port] = serviceName;
      portsSet.add(port);
      servicesSet.add(serviceName);
    });
  });

  return {
    hostDivs,
    hosts,
    openServices,
    ports: Array.from(portsSet).sort((a, b) => a - b),
    services: Array.from(servicesSet).sort()
  };
}

function isPortHostPercentileHighlightEnabled() {
  const toggle = document.getElementById("portHostPercentileToggle");
  return Boolean(toggle && toggle.checked);
}

function initializePortHostMatrixControls() {
  const toggle = document.getElementById("portHostPercentileToggle");
  if (!toggle || toggle.dataset.initialized === "true") {
    return;
  }

  toggle.addEventListener("change", () => {
    renderMatrixVisualizations();
  });
  toggle.dataset.initialized = "true";
}

function renderPortHostMatrix(hosts, ports, openServices, matrixConfig) {
  const portHostMatrix = document.getElementById("portHostMatrix");
  if (!portHostMatrix) {
    return;
  }

  if (hosts.length === 0 || ports.length === 0) {
    purgePlotlyElement("portHostMatrix");
    return;
  }

  const fixedPercentile = 0.95;
  const highlightPercentile = isPortHostPercentileHighlightEnabled();
  const sortedHosts = [...hosts].sort((a, b) => a.localeCompare(b, undefined, {
    numeric: true,
    sensitivity: "base"
  }));
  const hostServiceCounts = Object.fromEntries(
    sortedHosts.map(host => [
      host,
      Object.values(openServices[host] || {}).filter(Boolean).length
    ])
  );
  const portHostCounts = Object.fromEntries(
    ports.map(port => [
      port,
      sortedHosts.reduce((count, host) => count + (openServices[host][port] ? 1 : 0), 0)
    ])
  );
  const hostCountValues = Object.values(hostServiceCounts);
  const portCountValues = Object.values(portHostCounts);
  const tileSize = getDynamicTileSize(ports.length, sortedHosts.length, {
    minSize: 14,
    maxSize: 36
  });
  const dynamicHeight = Math.max(600, sortedHosts.length * tileSize + 160);
  const dynamicWidth = Math.max(900, ports.length * tileSize + 180);
  portHostMatrix.style.height = `${dynamicHeight}px`;
  portHostMatrix.style.width = `${dynamicWidth}px`;
  portHostMatrix.style.margin = "0 auto";

  const layout = {
    title: "",
    xaxis: {
      title: { text: "Port" },
      side: "top",
      type: "category",
      tickangle: -45,
      automargin: true,
      ticks: "outside",
      ticklen: 10,
      tickcolor: "rgba(0,0,0,0.05)",
      tickwidth: 1
    },
    yaxis: {
      type: "category",
      autorange: "reversed",
      automargin: true,
      ticks: "outside",
      ticklen: 10,
      tickcolor: "rgba(0,0,0,0.05)",
      tickwidth: 1
    },
    margin: { t: 80, l: 120, r: 50, b: 100 },
    dragmode: false,
    width: dynamicWidth,
    height: dynamicHeight,
    ...getPlotLayoutTheme()
  };

  const anomalyHostThreshold = highlightPercentile
    ? calculatePercentile(hostCountValues, fixedPercentile)
    : 0;
  const anomalyPortThreshold = highlightPercentile
    ? calculatePercentile(portCountValues, fixedPercentile)
    : 0;
  const z = sortedHosts.map(host =>
    ports.map(port => {
      const serviceName = openServices[host][port];
      if (!serviceName) {
        return 0;
      }

      const portHostCount = portHostCounts[port] || 0;
      const hostServiceCount = hostServiceCounts[host] || 0;
      if (highlightPercentile && portHostCount <= anomalyPortThreshold && hostServiceCount <= anomalyHostThreshold) {
        return 3;
      }

      return 1;
    })
  );
  const zText = sortedHosts.map(host =>
    ports.map(port => openServices[host][port] || "")
  );
  const hoverData = sortedHosts.map(host =>
    ports.map(port => [
      host,
      String(port),
      openServices[host][port] || "No open service",
      openServices[host][port] ? String(hostServiceCounts[host] || 0) : "0",
      openServices[host][port] ? String(portHostCounts[port] || 0) : "0",
      openServices[host][port]
        ? (() => {
          const portHostCount = portHostCounts[port] || 0;
          const hostServiceCount = hostServiceCounts[host] || 0;
          if (highlightPercentile && portHostCount <= anomalyPortThreshold && hostServiceCount <= anomalyHostThreshold) {
            return "95th percentile uncommon port";
          }
          return "Open service";
        })()
        : "No open service"
    ])
  );

  const data = [{
    z: z,
    x: ports.map(String),
    y: sortedHosts,
    text: zText,
    customdata: hoverData,
    type: "heatmap",
    colorscale: [
      [0, "#f3f4f6"],
      [0.332, "#f3f4f6"],
      [0.333, "#2ca02c"],
      [0.999, "#2ca02c"],
      [1, "#f59f00"]
    ],
    zmin: 0,
    zmax: 3,
    showscale: false,
    xgap: 2,
    ygap: 2,
    hoverongaps: false,
    hovertemplate: "Host: %{customdata[0]}<br>Port: %{customdata[1]}<br>Service: %{customdata[2]}<br>Open services on host: %{customdata[3]}<br>Hosts with port: %{customdata[4]}<br>Status: %{customdata[5]}<extra></extra>",
    text: zText
  }];

  if (portHostMatrix.data) {
    Plotly.react(portHostMatrix, data, layout, matrixConfig);
    return;
  }

  Plotly.newPlot(portHostMatrix, data, layout, matrixConfig);
}

function renderProtocolPortMatrix(hosts, ports, services, openServices, matrixConfig) {
  const protocolPortMatrix = document.getElementById("protocolPortMatrix");
  if (!protocolPortMatrix) {
    return;
  }

  if (hosts.length === 0 || ports.length === 0 || services.length === 0) {
    purgePlotlyElement("protocolPortMatrix");
    return;
  }

  const portCoverageCounts = Object.fromEntries(
    ports.map(port => [
      port,
      hosts.reduce((count, host) => count + (openServices[host][port] ? 1 : 0), 0)
    ])
  );
  const heatmapPorts = [...ports].sort((a, b) =>
    (portCoverageCounts[b] || 0) - (portCoverageCounts[a] || 0) || a - b
  );
  const z = services.map(service =>
    heatmapPorts.map(port => {
      let count = 0;
      for (const host of hosts) {
        if (openServices[host][port] === service) {
          count += 1;
        }
      }
      return count;
    })
  );

  const serviceTotals = z.map(row => row.reduce((a, b) => a + b, 0));
  const sortedIndices = serviceTotals
    .map((total, index) => ({ total, index }))
    .sort((a, b) => b.total - a.total)
    .map(item => item.index);
  const sortedServices = sortedIndices.map(index => services[index]);
  const sortedTotals = sortedIndices.map(index => serviceTotals[index]);
  const sortedZ = sortedIndices.map(index => z[index]);
  const heatmapTileSize = getDynamicTileSize(ports.length, sortedServices.length, {
    minSize: 14,
    maxSize: 36
  }) * 1.3225;
  const zText = sortedZ.map(row => row.map(value => (value > 0 ? value.toString() : "")));
  const hoverData = sortedServices.map((service, index) =>
    heatmapPorts.map(port => [String(port), service, String(sortedTotals[index])])
  );
  const yLabels = sortedServices.map((service, index) => `${service} (${sortedTotals[index]})`);

  const data = [{
    z: sortedZ,
    x: heatmapPorts.map(String),
    y: yLabels,
    text: zText,
    customdata: hoverData,
    type: "heatmap",
    colorscale: "BuGn",
    showscale: false,
    hoverongaps: false,
    hovertemplate: "Port: %{customdata[0]}<br>Service: %{customdata[1]}<br>Total: %{customdata[2]}<br>Occurrences: %{z}<extra></extra>",
    texttemplate: "%{text}",
    textfont: { color: "black", size: 12 }
  }];

  const dynamicHeight = Math.max(600, sortedServices.length * heatmapTileSize + 160);
  const dynamicWidth = Math.max(900, heatmapPorts.length * heatmapTileSize + 260);
  protocolPortMatrix.style.height = `${dynamicHeight}px`;
  protocolPortMatrix.style.width = `${dynamicWidth}px`;
  protocolPortMatrix.style.margin = "0 auto";

  const layout = {
    title: "",
    xaxis: {
      title: { text: "Port" },
      side: "top",
      type: "category",
      tickangle: -45,
      automargin: true
    },
    yaxis: {
      automargin: true
    },
    margin: { t: 80, l: 200, r: 50, b: 100 },
    width: dynamicWidth,
    height: dynamicHeight,
    dragmode: false,
    ...getPlotLayoutTheme()
  };

  if (protocolPortMatrix.data) {
    Plotly.react(protocolPortMatrix, data, layout, matrixConfig);
    return;
  }

  Plotly.newPlot(protocolPortMatrix, data, layout, matrixConfig);
}

function renderOpenPortsPerHostChart(hosts, openServices, matrixConfig) {
  const openPortsPerHostChart = document.getElementById("openPortsPerHostChart");
  if (!openPortsPerHostChart) {
    return;
  }

  if (hosts.length === 0) {
    purgePlotlyElement("openPortsPerHostChart");
    return;
  }

  const hostOverviewTable = document.getElementById("table-overview");
  const hostUniquenessScores = buildHostUniquenessScoreMap(hostOverviewTable);
  const hostIssueCounts = new Map();

  if (hostOverviewTable) {
    const hostOverviewHeaders = Array.from(hostOverviewTable.querySelectorAll("thead th")).map(header => (header.textContent || "").trim());
    const addressColumnIndex = hostOverviewHeaders.indexOf("Address");
    const hostnameColumnIndex = hostOverviewHeaders.indexOf("Hostname");

    if (addressColumnIndex !== -1) {
      hostOverviewTable.querySelectorAll("tbody tr").forEach(row => {
        const cells = row.querySelectorAll("td");
        if (cells.length <= addressColumnIndex) {
          return;
        }

        const address = (row.dataset.address || cells[addressColumnIndex].textContent || "").trim();
        if (!address || (window.isHostInScope && !window.isHostInScope(address))) {
          return;
        }

        const hostname = hostnameColumnIndex !== -1 && cells.length > hostnameColumnIndex
          ? (cells[hostnameColumnIndex].textContent || "").trim()
          : "";
        const issues = Number.parseInt((row.dataset.issues || "").trim(), 10) || 0;

        hostIssueCounts.set(address, issues);
        if (hostname && hostname !== "N/A") {
          hostIssueCounts.set(`${address} - ${hostname}`, issues);
        }
      });
    }
  }

  function getHostIssueCount(hostLabel) {
    if (hostIssueCounts.has(hostLabel)) {
      return hostIssueCounts.get(hostLabel) || 0;
    }

    const separatorIndex = hostLabel.indexOf(" - ");
    if (separatorIndex === -1) {
      return 0;
    }

    const address = hostLabel.slice(0, separatorIndex).trim();
    return hostIssueCounts.get(address) || 0;
  }

  function getHostUniquenessDetails(hostLabel) {
    if (hostUniquenessScores.has(hostLabel)) {
      return hostUniquenessScores.get(hostLabel) || null;
    }

    const separatorIndex = hostLabel.indexOf(" - ");
    if (separatorIndex === -1) {
      return hostUniquenessScores.get(hostLabel) || null;
    }

    const address = hostLabel.slice(0, separatorIndex).trim();
    return hostUniquenessScores.get(address) || null;
  }

  const hostOpenPortCounts = hosts
    .map(host => ({
      host,
      tcp: Object.entries(openServices[host] || {}).filter(([, service]) => service.startsWith("tcp:")).length,
      udp: Object.entries(openServices[host] || {}).filter(([, service]) => service.startsWith("udp:")).length,
      issues: getHostIssueCount(host),
      uniquenessDetails: getHostUniquenessDetails(host)
    }))
    .map(entry => ({
      ...entry,
      total: entry.tcp + entry.udp,
      uniqueness: entry.uniquenessDetails && Number.isFinite(entry.uniquenessDetails.score)
        ? entry.uniquenessDetails.score
        : 0,
      uniquenessContributors: entry.uniquenessDetails && Array.isArray(entry.uniquenessDetails.contributors)
        ? entry.uniquenessDetails.contributors
        : []
    }))
    .sort((a, b) => b.total - a.total || a.host.localeCompare(b.host));

  if (hostOpenPortCounts.length === 0) {
    purgePlotlyElement("openPortsPerHostChart");
    return;
  }

  const truncatedHosts = hostOpenPortCounts.map(entry => truncateLabel(entry.host));
  const maxIssueCount = Math.max(...hostOpenPortCounts.map(entry => entry.issues), 0);
  const maxOpenPortTotal = Math.max(...hostOpenPortCounts.map(entry => entry.total), 0);
  const xGuideValues = Array.from({ length: maxOpenPortTotal + 1 }, (_, value) => value);
  const xGuideLines = xGuideValues.map(value => ({
    type: "line",
    xref: "x",
    yref: "paper",
    x0: value,
    x1: value,
    y0: 0,
    y1: 1,
    layer: "above",
    line: {
      color: value === 0 ? "rgba(0,0,0,0.18)" : "rgba(0,0,0,0.08)",
      width: value === 0 ? 1.2 : 1
    }
  }));

  function hexToRgb(hex) {
    const normalized = (hex || "").replace("#", "");
    if (normalized.length !== 6) {
      return { r: 108, g: 117, b: 125 };
    }

    return {
      r: Number.parseInt(normalized.slice(0, 2), 16),
      g: Number.parseInt(normalized.slice(2, 4), 16),
      b: Number.parseInt(normalized.slice(4, 6), 16)
    };
  }

  function rgbToHex(rgb) {
    return `#${[rgb.r, rgb.g, rgb.b]
      .map(value => clamp(Math.round(value), 0, 255).toString(16).padStart(2, "0"))
      .join("")}`;
  }

  function blendHexColors(startHex, endHex, ratio) {
    const start = hexToRgb(startHex);
    const end = hexToRgb(endHex);
    const amount = clamp(ratio, 0, 1);

    return rgbToHex({
      r: start.r + ((end.r - start.r) * amount),
      g: start.g + ((end.g - start.g) * amount),
      b: start.b + ((end.b - start.b) * amount)
    });
  }

  function getIssueColor(issues, lightHex, darkHex) {
    if (maxIssueCount <= 0) {
      return blendHexColors(lightHex, darkHex, 0.55);
    }

    const normalized = issues / maxIssueCount;
    return blendHexColors(lightHex, darkHex, 0.28 + (normalized * 0.72));
  }

  const data = [{
    type: "bar",
    orientation: "h",
    y: truncatedHosts,
    x: hostOpenPortCounts.map(entry => entry.udp),
    text: hostOpenPortCounts.map(entry => (entry.udp > 0 ? `UDP: ${entry.udp}` : "")),
    textposition: "inside",
    cliponaxis: false,
    customdata: hostOpenPortCounts.map(entry => [entry.host, String(entry.tcp), String(entry.udp), String(entry.total), String(entry.issues)]),
    marker: {
      color: hostOpenPortCounts.map(entry => getIssueColor(entry.issues, "#ffe5b4", "#f59f00")),
      line: {
        color: hostOpenPortCounts.map(entry => getIssueColor(entry.issues, "#f3c677", "#d17d00")),
        width: 1.2
      },
      pattern: {
        shape: ""
      }
    },
    textfont: {
      color: "#ffffff"
    },
    hovertemplate: "%{customdata[0]}<br>TCP: %{customdata[1]}<br>UDP: %{customdata[2]}<br>Total open ports: %{customdata[3]}<br>Potential issues: %{customdata[4]}<extra></extra>",
    hoverlabel: {
      bgcolor: "#6c757d",
      bordercolor: "#495057",
      font: {
        color: "#ffffff"
      }
    }
  }, {
    type: "bar",
    orientation: "h",
    y: truncatedHosts,
    x: hostOpenPortCounts.map(entry => entry.tcp),
    text: hostOpenPortCounts.map(entry => (entry.tcp > 0 ? `TCP: ${entry.tcp}` : "")),
    textposition: "inside",
    insidetextanchor: "end",
    cliponaxis: false,
    customdata: hostOpenPortCounts.map(entry => [entry.host, String(entry.tcp), String(entry.udp), String(entry.total), String(entry.issues)]),
    marker: {
      color: hostOpenPortCounts.map(entry => getIssueColor(entry.issues, "#dbe8ff", "#0d6efd")),
      line: {
        color: hostOpenPortCounts.map(entry => getIssueColor(entry.issues, "#9ec5fe", "#0a58ca")),
        width: 1.2
      },
      pattern: {
        shape: ""
      }
    },
    textfont: {
      color: "#ffffff"
    },
    hovertemplate: "%{customdata[0]}<br>TCP: %{customdata[1]}<br>UDP: %{customdata[2]}<br>Total open ports: %{customdata[3]}<br>Potential issues: %{customdata[4]}<extra></extra>",
    hoverlabel: {
      bgcolor: "#6c757d",
      bordercolor: "#495057",
      font: {
        color: "#ffffff"
      }
    }
  }, {
    type: "scatter",
    mode: "markers",
    y: truncatedHosts,
    x: hostOpenPortCounts.map(entry => entry.uniqueness),
    xaxis: "x2",
    customdata: hostOpenPortCounts.map(entry => [
      entry.host,
      String(entry.tcp),
      String(entry.udp),
      String(entry.total),
      String(entry.issues),
      entry.uniqueness.toFixed(1),
      entry.uniquenessContributors.length > 0
        ? entry.uniquenessContributors.join(", ")
        : "No standout services"
    ]),
    marker: {
      size: 10,
      symbol: "diamond",
      opacity: 0.95,
      color: "#3f5f74",
      line: {
        color: getReportCssVar("--report-surface", "#f7f9fb"),
        width: 1.5
      }
    },
    hovertemplate: "%{customdata[0]}<br>Total open ports: %{customdata[3]}<br>TCP: %{customdata[1]}<br>UDP: %{customdata[2]}<br>Potential issues: %{customdata[4]}<br>Rarity: %{customdata[5]}<br>Drivers: %{customdata[6]}<extra></extra>",
    hoverlabel: {
      bgcolor: "#43505c",
      bordercolor: "#2f3943",
      font: {
        color: "#ffffff"
      }
    },
    showlegend: false,
    cliponaxis: false
  }];

  const dynamicHeight = Math.max(260, hostOpenPortCounts.length * 30 + 42);
  const dynamicWidth = Math.max(1100, Math.min(window.innerWidth - 24, 1700));
  const yCategoryRange = [hostOpenPortCounts.length - 0.5, -0.5];
  openPortsPerHostChart.style.height = `${dynamicHeight}px`;
  openPortsPerHostChart.style.width = `${dynamicWidth}px`;
  openPortsPerHostChart.style.margin = "0 auto";

  const layout = {
    title: "",
    margin: { t: 34, l: 220, r: 90, b: 28 },
    width: dynamicWidth,
    height: dynamicHeight,
    xaxis: {
      title: { text: "Open ports" },
      automargin: true,
      fixedrange: true,
      range: [0, maxOpenPortTotal + 0.5],
      showgrid: false,
      zeroline: false,
      rangemode: "tozero",
      tickmode: "array",
      tickvals: xGuideValues,
      ticktext: xGuideValues.map(String),
      showline: true,
      linecolor: "rgba(0,0,0,0.25)",
      linewidth: 1,
      ticks: "outside",
      ticklen: 6,
      tickcolor: "rgba(0,0,0,0.2)"
    },
    xaxis2: {
      title: { text: "Rarity" },
      overlaying: "x",
      side: "top",
      range: [0, 100],
      automargin: true,
      fixedrange: true,
      showgrid: false,
      zeroline: false,
      tickmode: "array",
      tickvals: [0, 20, 40, 60, 80, 100],
      ticktext: ["0", "20", "40", "60", "80", "100"],
      showline: true,
      linecolor: "rgba(0,0,0,0.22)",
      linewidth: 1,
      ticks: "outside",
      ticklen: 6,
      tickcolor: "rgba(0,0,0,0.2)"
    },
    yaxis: {
      automargin: true,
      fixedrange: true,
      categoryorder: "array",
      categoryarray: truncatedHosts,
      range: yCategoryRange,
      showgrid: false,
      tickson: "labels",
      ticks: "outside",
      ticklen: 6,
      tickcolor: "rgba(0,0,0,0.2)",
      showline: true,
      linecolor: "rgba(0,0,0,0.25)",
      linewidth: 1
    },
    shapes: xGuideLines,
    barmode: "stack",
    showlegend: false,
    dragmode: false,
    bargap: 0.24,
    ...getPlotLayoutTheme()
  };

  if (openPortsPerHostChart.data) {
    Plotly.react(openPortsPerHostChart, data, layout, matrixConfig);
    return;
  }

  Plotly.newPlot(openPortsPerHostChart, data, layout, matrixConfig);
}

function renderHostServiceGraph(hostDivs, hosts, matrixConfig) {
  const hostServiceGraph = document.getElementById("hostServiceGraph");
  if (!hostServiceGraph) {
    return;
  }

  if (hostDivs.length === 0 || hosts.length === 0) {
    purgePlotlyElement("hostServiceGraph");
    return;
  }

  const sortedHosts = [...hosts].sort((a, b) => a.localeCompare(b, undefined, {
    numeric: true,
    sensitivity: "base"
  }));
  const serviceGraphCounts = new Map();
  const hostServiceLabels = new Map();

  hostDivs.forEach(hostDiv => {
    const host = hostDiv.getAttribute("data-host");
    if (!host) {
      return;
    }

    const seenServiceLabels = new Set();
    hostDiv.querySelectorAll("span.port").forEach(span => {
      const graphLabel = (span.getAttribute("data-service-graph-label") || "").trim();
      if (!graphLabel || seenServiceLabels.has(graphLabel)) {
        return;
      }

      seenServiceLabels.add(graphLabel);
      serviceGraphCounts.set(graphLabel, (serviceGraphCounts.get(graphLabel) || 0) + 1);
    });

    hostServiceLabels.set(host, seenServiceLabels);
  });

  const sortedServicesForGraph = Array.from(serviceGraphCounts.entries())
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0], undefined, {
      numeric: true,
      sensitivity: "base"
    }))
    .map(([service]) => service);

  const labels = [...sortedHosts, ...sortedServicesForGraph];
  const hostIndex = new Map(sortedHosts.map((host, index) => [host, index]));
  const serviceOffset = sortedHosts.length;
  const serviceIndex = new Map(sortedServicesForGraph.map((service, index) => [service, serviceOffset + index]));
  const source = [];
  const target = [];
  const value = [];

  sortedHosts.forEach(host => {
    const seenServices = hostServiceLabels.get(host) || new Set();
    Array.from(seenServices).forEach(service => {
      source.push(hostIndex.get(host));
      target.push(serviceIndex.get(service));
      value.push(1);
    });
  });

  if (source.length === 0) {
    purgePlotlyElement("hostServiceGraph");
    return;
  }

  const dynamicHeight = Math.max(520, Math.max(sortedHosts.length, sortedServicesForGraph.length) * 24);
  const dynamicWidth = Math.max(1000, Math.min(window.innerWidth - 40, 1600));
  hostServiceGraph.style.height = `${dynamicHeight}px`;
  hostServiceGraph.style.width = `${dynamicWidth}px`;
  hostServiceGraph.style.margin = "0 auto";

  const data = [{
    type: "sankey",
    arrangement: "snap",
    node: {
      pad: 14,
      thickness: 14,
      line: {
        color: "rgba(0,0,0,0.15)",
        width: 1
      },
      label: labels,
      color: labels.map((_, index) => (index < serviceOffset ? "#6c757d" : "#0d6efd")),
      hovertemplate: "%{label}<extra></extra>"
    },
    link: {
      source: source,
      target: target,
      value: value,
      color: "rgba(13,110,253,0.18)",
      hovertemplate: "%{source.label} -> %{target.label}<extra></extra>"
    }
  }];

  const layout = {
    title: "",
    margin: { t: 20, l: 30, r: 30, b: 20 },
    width: dynamicWidth,
    height: dynamicHeight,
    font: {
      size: 12
    },
    ...getPlotLayoutTheme()
  };

  if (hostServiceGraph.data) {
    Plotly.react(hostServiceGraph, data, layout, matrixConfig);
    return;
  }

  Plotly.newPlot(hostServiceGraph, data, layout, matrixConfig);
}

function renderMatrixVisualizations() {
  if (!window.Plotly) {
    return;
  }

  const matrixConfig = {
    displayModeBar: false,
    scrollZoom: false
  };
  const matrixData = buildScopedMatrixData();

  renderPortHostMatrix(matrixData.hosts, matrixData.ports, matrixData.openServices, matrixConfig);
  renderProtocolPortMatrix(matrixData.hosts, matrixData.ports, matrixData.services, matrixData.openServices, matrixConfig);
  renderOpenPortsPerHostChart(matrixData.hosts, matrixData.openServices, matrixConfig);
  renderHostServiceGraph(matrixData.hostDivs, matrixData.hosts, matrixConfig);
}

window.renderMatrixVisualizations = renderMatrixVisualizations;

document.addEventListener("DOMContentLoaded", function() {
  initializePortHostMatrixControls();
  renderMatrixVisualizations();
});
        ]]></script>
        <script><![CDATA[
document.addEventListener("DOMContentLoaded", function() {
  document.querySelectorAll("details.visualization-card-collapsible").forEach(detailsElement => {
    detailsElement.addEventListener("toggle", function() {
      if (!detailsElement.open) {
        return;
      }

      window.requestAnimationFrame(() => refreshCollapsibleVisualization(detailsElement));
      window.setTimeout(() => refreshCollapsibleVisualization(detailsElement), 140);
    });

    if (detailsElement.open) {
      window.requestAnimationFrame(() => refreshCollapsibleVisualization(detailsElement));
    }
  });
});
        ]]></script>
  </xsl:template>

  <xsl:template match="/">
    <html lang="en">
      <xsl:call-template name="render-head"/>
      <body class="report-initializing" data-report-command="{/nmaprun/@args}" data-report-start="{/nmaprun/@start}" data-report-version="{/nmaprun/@version}">
        <xsl:call-template name="render-loading-overlay"/>
        <xsl:call-template name="render-navbar"/>
        <xsl:call-template name="render-about-dialog"/>
        <div id="reportContent" class="container-fluid px-4">
          <xsl:call-template name="render-summary"/>
          <xsl:call-template name="render-scanned-hosts"/>
          <xsl:call-template name="render-open-services"/>
          <xsl:call-template name="render-service-inventory"/>
          <xsl:call-template name="render-online-hosts"/>
        </div>
        <xsl:call-template name="render-footer"/>
        <xsl:call-template name="render-scripts"/>
        <xsl:call-template name="render-visualization-scripts"/>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
