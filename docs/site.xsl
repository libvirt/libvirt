<?xml version="1.0"?>
<xsl:stylesheet
  xmlns:html="http://www.w3.org/1999/xhtml"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:exsl="http://exslt.org/common"
  exclude-result-prefixes="xsl exsl"
  version="1.0">

  <xsl:import href="page.xsl"/>

  <xsl:param name="builddir" select="'..'"/>

  <xsl:template match="html:div[@id='include']" mode="content">
    <xsl:call-template name="include"/>
  </xsl:template>

  <xsl:template name="include">
    <xsl:variable name="inchtml">
      <xsl:copy-of select="document(concat($builddir, '/docs/', @filename))"/>
    </xsl:variable>

    <xsl:apply-templates select="exsl:node-set($inchtml)/html:html/html:body/*" mode="content"/>
  </xsl:template>

  <xsl:output method="xml" omit-xml-declaration="yes" encoding="UTF-8" indent="yes"/>

  <xsl:template match="/">
    <xsl:apply-templates select="." mode="page">
      <xsl:with-param name="pagesrc" select="$pagesrc"/>
      <xsl:with-param name="timestamp" select="$timestamp"/>
      <xsl:with-param name="link_href_base" select="$href_base"/>
      <xsl:with-param name="asset_href_base" select="$href_base"/>
    </xsl:apply-templates>
  </xsl:template>

</xsl:stylesheet>
