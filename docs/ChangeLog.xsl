<?xml version="1.0"?>
<!-- this stylesheet builds the ChangeLog.html -->
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

  <!-- Generate XHTML-1.0 transitional -->
  <xsl:output method="xml" encoding="ISO-8859-1" indent="yes"
      doctype-public="-//W3C//DTD XHTML 1.0//EN"
      doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"/>

  <xsl:template match="item">
    <li><xsl:apply-templates/></li>
  </xsl:template>

  <xsl:template match="entry">
    <p>
      <span class="author"><xsl:value-of select="@who"/> </span>
      <span class="date"><xsl:value-of select="@date"/> </span>
      <span class="timezone"><xsl:value-of select="@timezone"/> </span>
    </p>
    <ul>
      <xsl:apply-templates select="item"/>
    </ul>
  </xsl:template>

  <xsl:template match="log">
    <html>
      <body>
        <h1>Log of recent changes to libvirt</h1>
        <div id="changelog">
          <xsl:apply-templates select="entry"/>
        </div>
      </body>
    </html>
  </xsl:template>

</xsl:stylesheet>
