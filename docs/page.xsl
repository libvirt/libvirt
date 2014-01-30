<?xml version="1.0"?>
<xsl:stylesheet
  xmlns="http://www.w3.org/1999/xhtml"
  xmlns:html="http://www.w3.org/1999/xhtml"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:exsl="http://exslt.org/common"
  exclude-result-prefixes="xsl exsl html"
  version="1.0">

  <!-- The sitemap.html.in page contains the master navigation structure -->
  <xsl:variable name="sitemap" select="document('sitemap.html.in')/html:html/html:body/html:div[@id='sitemap']"/>

  <xsl:template match="html:code[@class='docref']" mode="content">
    <xsl:variable name="name"><xsl:value-of select="."/></xsl:variable>
    <a href="html/libvirt-libvirt.html#{$name}"><code><xsl:value-of select="$name"/></code></a>
  </xsl:template>

  <xsl:template match="node() | @*" mode="content">
    <xsl:copy>
      <xsl:apply-templates select="node() | @*" mode="content"/>
    </xsl:copy>
  </xsl:template>


  <xsl:template match="html:ul[@id='toc']" mode="content">
    <xsl:call-template name="toc"/>
  </xsl:template>

  <xsl:template match="html:div[@id='include']" mode="content">
    <xsl:call-template name="include"/>
  </xsl:template>

  <!-- This processes the sitemap to form a context sensitive
       navigation menu for the current page -->
  <xsl:template match="html:ul" mode="menu">
    <xsl:param name="pagename"/>
    <xsl:param name="level"/>
    <ul class="{concat('l', $level)}">
      <xsl:for-each select="html:li">
        <!-- The extra div tag here works around an IE6 whitespace collapsing problem -->
        <li><div>
          <!-- A menu is active if there is an 'a' tag with
               a href matching this pagename at this level
               or a child menu -->
          <xsl:variable name="class">
            <xsl:choose>
              <xsl:when test="count(.//html:a[@href = $pagename]) > 0">
                <xsl:text>active</xsl:text>
              </xsl:when>
              <xsl:otherwise>
                <xsl:text>inactive</xsl:text>
              </xsl:otherwise>
            </xsl:choose>
          </xsl:variable>

          <!-- A menu should use a 'span' instead of 'a' if
               the immediate 'a' tag has href matching the
               current pagename -->
          <xsl:choose>
            <xsl:when test="$pagename = html:a/@href">
              <span class="{$class}"><xsl:value-of select="html:a"/></span>
            </xsl:when>
            <xsl:when test="starts-with(html:a/@href, 'http://wiki.libvirt.org')">
              <a title="{./html:span}" class="{$class}" href="{html:a/@href}"><xsl:value-of select="html:a"/></a>
            </xsl:when>
            <xsl:otherwise>
              <a title="{./html:span}" class="{$class}" href="{concat($href_base, html:a/@href)}"><xsl:value-of select="html:a"/></a>
            </xsl:otherwise>
          </xsl:choose>

          <!-- A sub-menu should only be expanded it contains
               an 'a' tag with href matching this pagename -->
          <xsl:if test="count(.//html:a[@href = $pagename]) > 0">
            <xsl:apply-templates select="html:ul" mode="menu">
              <xsl:with-param name="pagename" select="$pagename"/>
              <xsl:with-param name="level" select="$level + 1"/>
            </xsl:apply-templates>
          </xsl:if>
        </div></li>
      </xsl:for-each>
    </ul>
  </xsl:template>

  <xsl:template name="toc">
    <ul>
      <xsl:for-each select="/html:html/html:body/html:h2[count(html:a) = 1]">
        <xsl:variable name="thish2" select="."/>
        <li>
          <a href="#{html:a/@name}"><xsl:value-of select="html:a/text()"/></a>
          <xsl:if test="count(./following-sibling::html:h3[preceding-sibling::html:h2[1] = $thish2 and count(html:a) = 1]) > 0">
            <ul>
              <xsl:for-each select="./following-sibling::html:h3[preceding-sibling::html:h2[1] = $thish2 and count(html:a) = 1]">
                <xsl:variable name="thish3" select="."/>
                <li>
                  <a href="#{html:a/@name}"><xsl:value-of select="html:a/text()"/></a>
                  <xsl:if test="count(./following-sibling::html:h4[preceding-sibling::html:h3[1] = $thish3 and count(html:a) = 1]) > 0">
                    <ul>
                      <xsl:for-each select="./following-sibling::html:h4[preceding-sibling::html:h3[1] = $thish3 and count(html:a) = 1]">
                        <xsl:variable name="thish4" select="."/>
                        <li>
                          <a href="#{html:a/@name}"><xsl:value-of select="html:a/text()"/></a>
                          <xsl:if test="count(./following-sibling::html:h5[preceding-sibling::html:h4[1] = $thish4 and count(html:a) = 1]) > 0">
                            <ul>
                              <xsl:for-each select="./following-sibling::html:h5[preceding-sibling::html:h4[1] = $thish4 and count(html:a) = 1]">
                                <xsl:variable name="thish5" select="."/>
                                <li>
                                  <a href="#{html:a/@name}"><xsl:value-of select="html:a/text()"/></a>
                                  <xsl:if test="count(./following-sibling::html:h6[preceding-sibling::html:h5[1] = $thish5 and count(html:a) = 1]) > 0">
                                    <ul>
                                      <xsl:for-each select="./following-sibling::html:h6[preceding-sibling::html:h5[1] = $thish5 and count(html:a) = 1]">
                                        <li>
                                          <a href="#{html:a/@name}"><xsl:value-of select="html:a/text()"/></a>
                                        </li>
                                      </xsl:for-each>
                                    </ul>
                                  </xsl:if>
                                </li>
                              </xsl:for-each>
                            </ul>
                          </xsl:if>
                        </li>
                      </xsl:for-each>
                    </ul>
                  </xsl:if>
                </li>
              </xsl:for-each>
            </ul>
          </xsl:if>
        </li>
      </xsl:for-each>
    </ul>
  </xsl:template>

  <!-- This is the master page structure -->
  <xsl:template match="/" mode="page">
    <xsl:param name="pagename"/>
    <html>
      <xsl:comment>
        This file is autogenerated from <xsl:value-of select="$pagename"/>.in
        Do not edit this file. Changes will be lost.
      </xsl:comment>
      <head>
        <link rel="stylesheet" type="text/css" href="{$href_base}main.css"/>
        <link rel="SHORTCUT ICON" href="{$href_base}32favicon.png"/>
        <title>libvirt: <xsl:value-of select="html:html/html:body/html:h1"/></title>
        <meta name="description" content="libvirt, virtualization, virtualization API"/>
      </head>
      <body>
        <div id="header">
          <div id="headerLogo"/>
          <div id="headerSearch">
            <form action="{$href_base}search.php" enctype="application/x-www-form-urlencoded" method="get">
              <div>
                <input id="query" name="query" type="text" size="12" value=""/>
                <input id="submit" name="submit" type="submit" value="Search"/>
              </div>
            </form>
          </div>
        </div>
        <div id="body">
          <div id="menu">
            <xsl:apply-templates select="exsl:node-set($sitemap)/html:ul" mode="menu">
              <xsl:with-param name="pagename" select="$pagename"/>
              <xsl:with-param name="level" select="0"/>
            </xsl:apply-templates>
          </div>
          <div id="content">
            <xsl:apply-templates select="/html:html/html:body/*" mode="content"/>
          </div>
        </div>
        <div id="footer">
          <p id="sponsor">
	    Sponsored by:<br/>
            <a href="http://et.redhat.com/"><img src="{$href_base}et.png" alt="Project sponsored by Red Hat Emerging Technology"/></a>
          </p>
        </div>
      </body>
    </html>
  </xsl:template>

  <xsl:template name="include">
    <xsl:variable name="inchtml">
      <xsl:copy-of select="document(@filename)"/>
    </xsl:variable>

    <xsl:apply-templates select="exsl:node-set($inchtml)/html:html/html:body/*" mode="content"/>
  </xsl:template>

  <xsl:template match="html:h2 | html:h3 | html:h4 | html:h5 | html:h6" mode="content">
    <xsl:element name="{name()}">
      <xsl:apply-templates mode="copy" />
      <xsl:if test="./html:a/@name">
        <a class="headerlink" href="#{html:a/@name}" title="Permalink to this headline">&#xb6;</a>
      </xsl:if>
    </xsl:element>
  </xsl:template>

  <xsl:template match="text()" mode="copy">
    <xsl:value-of select="."/>
  </xsl:template>

  <xsl:template match="node()" mode="copy">
    <xsl:element name="{name()}">
      <xsl:copy-of select="./@*"/>
      <xsl:apply-templates mode="copy" />
    </xsl:element>
  </xsl:template>
</xsl:stylesheet>
