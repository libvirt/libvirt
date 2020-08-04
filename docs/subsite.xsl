<?xml version="1.0"?>
<xsl:stylesheet
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:exsl="http://exslt.org/common"
  exclude-result-prefixes="xsl exsl"
  version="1.0">

  <xsl:import href="page.xsl"/>

  <xsl:output
    method="xml"
    encoding="UTF-8"
    indent="yes"/>

  <xsl:variable name="href_base" select="'../'"/>

  <xsl:template match="/">
    <xsl:apply-templates select="." mode="page">
      <xsl:with-param name="pagesrc" select="$pagesrc"/>
      <xsl:with-param name="timestamp" select="$timestamp"/>
    </xsl:apply-templates>
  </xsl:template>

</xsl:stylesheet>
