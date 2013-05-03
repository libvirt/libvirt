<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
                xmlns:html="http://www.w3.org/1999/xhtml"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:output method="xml" encoding="UTF-8" indent="no"/>



<xsl:template match="/">
  <xsl:apply-templates/>
</xsl:template>



<xsl:template match="@*|node()">
  <xsl:copy>
    <xsl:apply-templates select="@*|node()"/>
  </xsl:copy>
</xsl:template>



<!-- resolve b/i/code tags in a first pass, because they interfere with line
     wrapping in the second pass -->
<xsl:template match="html:b">*<xsl:apply-templates/>*</xsl:template>
<xsl:template match="html:i">'<xsl:apply-templates/>'</xsl:template>
<xsl:template match="html:code">"<xsl:apply-templates/>"</xsl:template>

</xsl:stylesheet>
