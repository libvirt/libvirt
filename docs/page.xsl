<?xml version="1.0"?>
<xsl:stylesheet
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:exsl="http://exslt.org/common"
  exclude-result-prefixes="xsl exsl"
  version="1.0">

  <!-- The sitemap.html.in page contains the master navigation structure -->
  <xsl:variable name="sitemap" select="document('sitemap.html.in')/html/body/div[@id='sitemap']"/>

  <xsl:template match="code[@class='docref']" mode="content">
    <xsl:variable name="name"><xsl:value-of select="."/></xsl:variable>
    <a href="html/libvirt-libvirt.html#{$name}"><code><xsl:value-of select="$name"/></code></a>
  </xsl:template>

  <xsl:template match="node() | @*" mode="content">
    <xsl:copy>
      <xsl:apply-templates select="node() | @*" mode="content"/>
    </xsl:copy>
  </xsl:template>


  <xsl:template match="ul[@id='toc']" mode="content">
    <xsl:call-template name="toc"/>
  </xsl:template>

  <!-- This processes the sitemap to form a context sensitive
       navigation menu for the current page -->
  <xsl:template match="ul" mode="menu">
    <xsl:param name="pagename"/>
    <xsl:param name="level"/>
    <ul class="{concat('l', $level)}">
      <xsl:for-each select="li">
        <!-- The extra div tag here works around an IE6 whitespace collapsing problem -->
        <li><div>
          <!-- A menu is active if there is an 'a' tag with
               a href matching this pagename at this level
               or a child menu -->
          <xsl:variable name="class">
            <xsl:choose>
              <xsl:when test="count(.//a[@href = $pagename]) > 0">
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
            <xsl:when test="$pagename = a/@href">
              <span class="{$class}"><xsl:value-of select="a"/></span>
            </xsl:when>
            <xsl:when test="a/@href = 'http://wiki.libvirt.org'">
              <a title="{./span}" class="{$class}" href="{a/@href}"><xsl:value-of select="a"/></a>
            </xsl:when>
            <xsl:otherwise>
              <a title="{./span}" class="{$class}" href="{concat($href_base, a/@href)}"><xsl:value-of select="a"/></a>
            </xsl:otherwise>
          </xsl:choose>

          <!-- A sub-menu should only be expanded it contains
               an 'a' tag with href matching this pagename -->
          <xsl:if test="count(.//a[@href = $pagename]) > 0">
            <xsl:apply-templates select="ul" mode="menu">
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
      <xsl:for-each select="/html/body/h2[count(a) = 1]">
        <xsl:variable name="thish2" select="."/>
        <li>
          <a href="#{a/@name}"><xsl:value-of select="a/text()"/></a>
          <xsl:if test="count(./following-sibling::h3[preceding-sibling::h2[1] = $thish2 and count(a) = 1]) > 0">
            <ul>
              <xsl:for-each select="./following-sibling::h3[preceding-sibling::h2[1] = $thish2 and count(a) = 1]">
                <xsl:variable name="thish3" select="."/>
                <li>
                  <a href="#{a/@name}"><xsl:value-of select="a/text()"/></a>
                  <xsl:if test="count(./following-sibling::h4[preceding-sibling::h3[1] = $thish3 and count(a) = 1]) > 0">
                    <ul>
                      <xsl:for-each select="./following-sibling::h4[preceding-sibling::h3[1] = $thish3 and count(a) = 1]">
                        <xsl:variable name="thish4" select="."/>
                        <li>
                          <a href="#{a/@name}"><xsl:value-of select="a/text()"/></a>
                          <xsl:if test="count(./following-sibling::h5[preceding-sibling::h4[1] = $thish4 and count(a) = 1]) > 0">
                            <ul>
                              <xsl:for-each select="./following-sibling::h5[preceding-sibling::h4[1] = $thish4 and count(a) = 1]">
                                <xsl:variable name="thish5" select="."/>
                                <li>
                                  <a href="#{a/@name}"><xsl:value-of select="a/text()"/></a>
                                  <xsl:if test="count(./following-sibling::h6[preceding-sibling::h5[1] = $thish5 and count(a) = 1]) > 0">
                                    <ul>
                                      <xsl:for-each select="./following-sibling::h6[preceding-sibling::h5[1] = $thish5 and count(a) = 1]">
                                        <li>
                                          <a href="#{a/@name}"><xsl:value-of select="a/text()"/></a>
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
        <title>libvirt: <xsl:value-of select="html/body/h1"/></title>
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
            <xsl:apply-templates select="exsl:node-set($sitemap)/ul" mode="menu">
              <xsl:with-param name="pagename" select="$pagename"/>
              <xsl:with-param name="level" select="0"/>
            </xsl:apply-templates>
          </div>
          <div id="content">
            <xsl:apply-templates select="/html/body/*" mode="content"/>
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

</xsl:stylesheet>
