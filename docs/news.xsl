<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
                xmlns:html="http://www.w3.org/1999/xhtml"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="text" encoding="UTF-8"/>

  <xsl:template match="/">
    <xsl:text>libvirt releases
================
</xsl:text>
    <xsl:apply-templates select="html:html/html:body/*"/>
  </xsl:template>

  <xsl:template match="html:h1"/>
  <xsl:template match="html:p"/>

  <xsl:template match="html:h3">
    <xsl:text>
</xsl:text>
    <xsl:text># </xsl:text>
    <xsl:apply-templates/>
    <xsl:text>

</xsl:text>
  </xsl:template>

  <xsl:template match="html:ul">
    <xsl:apply-templates select="html:li"/>
  </xsl:template>

  <xsl:template match="html:li">
    <xsl:text>   * </xsl:text>
    <xsl:apply-templates select="html:strong|*/html:li"/>
  </xsl:template>

  <xsl:template match="html:li/*/html:li">
    <xsl:text>      - </xsl:text>
    <xsl:apply-templates/>
    <xsl:text>
</xsl:text>
  </xsl:template>

  <xsl:template match="html:strong">
    <xsl:apply-templates/>
    <xsl:text>

</xsl:text>
  </xsl:template>

</xsl:stylesheet>
