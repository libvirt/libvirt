<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:exsl="http://exslt.org/common"
  extension-element-prefixes="exsl"
  exclude-result-prefixes="exsl">

  <xsl:import href="../site.xsl"/>

  <xsl:variable name="href_base">../</xsl:variable>
  <xsl:variable name="menu_name">Examples Menu</xsl:variable>

  <xsl:variable name="toc">
    <form action="../search.php"
          enctype="application/x-www-form-urlencoded" method="get">
      <input name="query" type="text" size="20" value=""/>
      <input name="submit" type="submit" value="Search ..."/>
    </form>
    <ul><!-- style="margin-left: -1em" -->
      <li><a href="{$href_base}index.html">Home</a></li>
      <li><a style="font-weight:bold"
             href="{$href_base}docs.html">Developer Menu</a></li>
      <li><a style="font-weight:bold"
             href="{$href_base}html/index.html">API Menu</a></li>
      <xsl:for-each select="/examples/sections/section">
        <li><a href="#{@name}"><xsl:value-of select="@name"/> Examples</a></li>
      </xsl:for-each>
      <li><a href="{$href_base}guidelines.html">XML Guidelines</a></li>
    </ul>
  </xsl:variable>

  <xsl:template match="include">
    <xsl:variable name="header" select="substring-before(substring-after(., '/'), '&gt;')"/>
    <xsl:variable name="doc" select="concat('../html/libvirt-', $header, 'tml')"/>
    <li><a href="{$doc}"><xsl:value-of select="."/></a></li>
  </xsl:template>

  <xsl:template match="typedef">
    <xsl:variable name="name" select="@name"/>
    <xsl:variable name="header" select="concat(@file, '.h')"/>
    <xsl:variable name="doc" select="concat('../html/libvirt-', @file, '.html#', $name)"/>
    <li> line <xsl:value-of select="@line"/>: Type <a href="{$doc}"><xsl:value-of select="$name"/></a> from <xsl:value-of select="$header"/></li>
  </xsl:template>

  <xsl:template match="function">
    <xsl:variable name="name" select="@name"/>
    <xsl:variable name="header" select="concat(@file, '.h')"/>
    <xsl:variable name="doc" select="concat('../html/libvirt-', @file, '.html#', $name)"/>
    <li> line <xsl:value-of select="@line"/>: Function <a href="{$doc}"><xsl:value-of select="$name"/></a> from <xsl:value-of select="$header"/></li>
  </xsl:template>

  <xsl:template match="macro">
    <xsl:variable name="name" select="@name"/>
    <xsl:variable name="header" select="concat(@file, '.h')"/>
    <xsl:variable name="doc" select="concat('../html/libvirt-', @file, '.html#', $name)"/>
    <li> line <xsl:value-of select="@line"/>: Macro <a href="{$doc}"><xsl:value-of select="$name"/></a> from <xsl:value-of select="$header"/></li>
  </xsl:template>

  <xsl:template match="example">
    <xsl:variable name="filename" select="string(@filename)"/>
    <h3><a name="{$filename}" href="{$filename}"><xsl:value-of select="$filename"/></a>: <xsl:value-of select="synopsis"/></h3>
    <p><xsl:value-of select="purpose"/></p>
    <p>Uses:</p>
    <ul>
    <xsl:for-each select="uses/*">
      <xsl:sort select="@line" data-type="number"/>
      <xsl:apply-templates select='.'/>
    </xsl:for-each>
    </ul>
    <p>Usage:</p>
    <p><xsl:value-of select="usage"/></p>
    <p>Author: <xsl:value-of select="author"/></p>
  </xsl:template>

  <xsl:template match="section">
    <li><p> <a href="#{@name}"><xsl:value-of select="@name"/></a> :</p>
    <ul>
    <xsl:for-each select="example">
      <xsl:sort select='.'/>
      <xsl:variable name="filename" select="@filename"/>
      <li> <a href="#{$filename}"><xsl:value-of select="$filename"/></a>: <xsl:value-of select="/examples/example[@filename = $filename]/synopsis"/></li>
    </xsl:for-each>
    </ul>
    </li>
  </xsl:template>

  <xsl:template match="sections">
    <p> The examples are stored per section depending on the main focus
    of the example:</p>
    <ul>
    <xsl:for-each select="section">
      <xsl:sort select='.'/>
      <xsl:apply-templates select='.'/>
    </xsl:for-each>
    </ul>
    <p> Getting the compilation options and libraries dependancies needed
to generate binaries from the examples is best done on Linux/Unix by using
the pkg-config data which should have been installed as part of <i>make
install</i> step or when installing the libvirt development package:</p>
<pre>gcc -o example example.c `pkg-config libvirt --libs`</pre>
  </xsl:template>

  <xsl:template name="sections-list">
    <xsl:for-each select="sections/section">
      <xsl:variable name="section" select="@name"/>
      <h2> <a name="{$section}"></a><xsl:value-of select="$section"/> Examples</h2>
      <xsl:apply-templates select='/examples/example[section = $section]'/>
    </xsl:for-each>
  </xsl:template>

  <xsl:template match="examples">
    <xsl:variable name="title">Libvirt set of C code examples</xsl:variable>
     <xsl:document href="index.html" method="xml" encoding="ISO-8859-1"
         doctype-public="-//W3C//DTD XHTML 1.0 Transitional//EN"
     doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
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
	      <xsl:apply-templates select="sections"/>
	      <xsl:call-template name="sections-list"/>
	    </div>
	  </div>
	  <xsl:call-template name="linkList2"/>
	  <xsl:call-template name="bottom"/>
	</div>
	</body>
      </html>
    </xsl:document>
  </xsl:template>

</xsl:stylesheet>
