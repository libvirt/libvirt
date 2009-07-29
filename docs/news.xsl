<?xml version="1.0"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                version="1.0">
  <xsl:output method="text" encoding="UTF-8"/>

  <xsl:template match="/">
    <xsl:text>
        NEWS file for libvirt

  Note that this is automatically generated from the news webpage at:
       http://libvirt.org/news.html

</xsl:text>
    <xsl:apply-templates select="html/body/*"/>
  </xsl:template>
  <xsl:template match="h1"/>

  <xsl:template match="h3">
    <xsl:text>
</xsl:text>
    <xsl:apply-templates/>
    <xsl:text>:
</xsl:text>
  </xsl:template>
  <xsl:template match="ul">
    <xsl:apply-templates select=".//li"/>
    <xsl:text>
</xsl:text>
  </xsl:template>
  <xsl:template match="li">
    <xsl:text>   - </xsl:text>
    <xsl:value-of select="."/>
    <xsl:text>
</xsl:text>
  </xsl:template>
  <xsl:template match="a">
    <xsl:value-of select="."/>
    <xsl:text> at
</xsl:text>
    <xsl:value-of select="@href"/>
    <xsl:text>
</xsl:text>
  </xsl:template>
  <xsl:template match="p">
  </xsl:template>
</xsl:stylesheet>
