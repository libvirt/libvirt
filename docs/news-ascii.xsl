<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="text" encoding="UTF-8"/>

  <!-- This XSLT stylesheet can be applied to the XML version of the release
       notes to produce a plain text document. The output document is not
       formatted properly and needs to be processed further -->

  <!-- Document -->
  <xsl:template match="/libvirt">
    <xsl:text>libvirt releases
================
</xsl:text>
    <xsl:apply-templates select="release"/>
    <xsl:text>
==============================================================================
Older libvirt releases didn't have proper release notes: if you are interested
in changes between them, you should check out ChangeLog* and docs/news-*.html.
</xsl:text>
  </xsl:template>

  <!-- Release -->
  <xsl:template match="release">
    <xsl:text>
# </xsl:text>
    <xsl:value-of select="@version"/>
    <xsl:text> (</xsl:text>
    <xsl:value-of select="@date"/>
    <xsl:text>)
</xsl:text>
    <xsl:apply-templates select="section"/>
  </xsl:template>

  <!-- Section -->
  <xsl:template match="section">
    <xsl:text>
* </xsl:text>
    <xsl:value-of select="@title"/>
    <xsl:text>
</xsl:text>
    <xsl:apply-templates select="change"/>
  </xsl:template>

  <!-- Change -->
  <xsl:template match="change">
    <xsl:text>
</xsl:text>
    <xsl:apply-templates select="summary"/>
    <xsl:apply-templates select="description"/>
  </xsl:template>

  <!-- Change summary -->
  <xsl:template match="summary">
    <xsl:text>- </xsl:text>
    <xsl:value-of select="normalize-space()"/>
    <xsl:text>
</xsl:text>
  </xsl:template>

  <!-- Change description -->
  <xsl:template match="description">
    <xsl:text>|</xsl:text> <!-- This will be removed when reformatting -->
    <xsl:value-of select="normalize-space()"/>
    <xsl:text>
</xsl:text>
  </xsl:template>

</xsl:stylesheet>
