<?xml version="1.0"?>
<!-- this stylesheet builds the ChangeLog.html -->
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

  <!-- Import the rest of the site stylesheets -->
  <xsl:import href="site.xsl"/>

  <!-- Generate XHTML-1.0 transitional -->
  <xsl:output method="xml" encoding="ISO-8859-1" indent="yes"
      doctype-public="-//W3C//DTD XHTML 1.0 Transitional//EN"
      doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"/>

  <xsl:param name="module">libvirt</xsl:param>

  <!-- The table of content for the HTML page -->
  <xsl:variable name="menu_name">API Menu</xsl:variable>
  <xsl:variable name="develtoc">
    <form action="../search.php"
          enctype="application/x-www-form-urlencoded" method="get">
      <input name="query" type="text" size="20" value=""/>
      <input name="submit" type="submit" value="Search ..."/>
    </form>
    <ul><!-- style="margin-left: -1em" -->
      <li><a style="font-weight:bold"
             href="{$href_base}index.html">Main Menu</a></li>
      <li><a style="font-weight:bold" 
             href="{$href_base}html/index.html">Modules Index</a></li>
      <li><a style="font-weight:bold"
             href="index.html">API Menu</a></li>
    </ul>
  </xsl:variable>

  <xsl:template match="bug">
    <a href="https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id={@number}">
    <xsl:value-of select="@number"/></a>
  </xsl:template>
  
  <xsl:template match="item">
    <li><xsl:apply-templates/></li>
  </xsl:template>

  <xsl:template match="entry">
    
    <p>
    <b><xsl:value-of select="@who"/></b>
       <xsl:text> </xsl:text>
       <xsl:value-of select="@date"/>
       <xsl:text> </xsl:text>
       <xsl:value-of select="@timezone"/>
    <ul>
      <xsl:apply-templates select="item"/>
    </ul>
    </p>
  </xsl:template>

  <xsl:template match="log">
    <xsl:variable name="title">ChangeLog last entries of <xsl:value-of select="$module"/></xsl:variable>
      <html>
        <head>
          <xsl:call-template name="style"/>
          <xsl:element name="title">
            <xsl:value-of select="$title"/>
          </xsl:element>
        </head>
	<body>
	<div id="container">
	  <div id="intro">
	    <div id="adjustments"/>
	    <div id="pageHeader"/>
	    <div id="content2">
	      <xsl:call-template name="titlebox">
		<xsl:with-param name="title" select="$title"/>
	      </xsl:call-template>
	      <xsl:apply-templates select="entry"/>
	    </div>
	  </div>
	  <xsl:call-template name="linkList2"/>
	  <xsl:call-template name="bottom"/>
	</div>
	</body>
      </html>
  </xsl:template>

</xsl:stylesheet>
