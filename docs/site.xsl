<?xml version="1.0"?>
<xsl:stylesheet
  xmlns:html="http://www.w3.org/1999/xhtml"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:exsl="http://exslt.org/common"
  exclude-result-prefixes="xsl exsl"
  version="1.0">

  <xsl:import href="page.xsl"/>

  <xsl:output
    method="xml"
    encoding="UTF-8"
    indent="yes"
    doctype-public="-//W3C//DTD XHTML 1.0 Strict//EN"
    doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"/>

  <xsl:variable name="href_base">
    <xsl:choose>
      <xsl:when test="$pagename = '404.html'">
        <xsl:value-of select="'/'"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="''"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:variable>

  <xsl:template match="/">
    <xsl:apply-templates select="." mode="page">
      <xsl:with-param name="pagename" select="$pagename"/>
      <xsl:with-param name="timestamp" select="$timestamp"/>
    </xsl:apply-templates>
  </xsl:template>

</xsl:stylesheet>
