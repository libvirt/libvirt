<?xml version="1.0"?>
<!--
  Stylesheet to generate the HTML documentation from an XML API descriptions:
  xsltproc newapi.xsl libvirt-api.xml

  Daniel Veillard
-->
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:exsl="http://exslt.org/common"
  xmlns:str="http://exslt.org/strings"
  extension-element-prefixes="exsl str"
  exclude-result-prefixes="exsl str">

  <!-- Import the main part of the site stylesheets -->
  <xsl:import href="page.xsl"/>

  <!-- Generate XHTML-1.0 transitional -->
  <xsl:output method="xml" encoding="UTF-8" indent="yes"
      doctype-public="-//W3C//DTD XHTML 1.0//EN"
      doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"/>

  <!-- Build keys for all symbols -->
  <xsl:key name="symbols" match="/api/symbols/*" use="@name"/>

  <!-- the target directory for the HTML output -->
  <xsl:variable name="htmldir">html</xsl:variable>
  <xsl:variable name="href_base">../</xsl:variable>

  <xsl:template name="navbar">
    <xsl:variable name="previous" select="preceding-sibling::file[1]"/>
    <xsl:variable name="next" select="following-sibling::file[1]"/>
    <table class="navigation" width="100%" summary="Navigation header"
           cellpadding="2" cellspacing="2">
      <tr valign="middle">
        <xsl:if test="$previous">
          <td><a accesskey="p" href="libvirt-{$previous/@name}.html"><img src="left.png" width="24" height="24" border="0" alt="Prev"></img></a></td>
	  <th align="left"><a href="libvirt-{$previous/@name}.html"><xsl:value-of select="$previous/@name"/></a></th>
	</xsl:if>
        <td><a accesskey="u" href="index.html"><img src="up.png" width="24" height="24" border="0" alt="Up"></img></a></td>
	<th align="left"><a href="index.html">API documentation</a></th>
        <td><a accesskey="h" href="../index.html"><img src="home.png" width="24" height="24" border="0" alt="Home"></img></a></td>
        <th align="center"><a href="../index.html">The virtualization API</a></th>
        <xsl:if test="$next">
	  <th align="right"><a href="libvirt-{$next/@name}.html"><xsl:value-of select="$next/@name"/></a></th>
          <td><a accesskey="n" href="libvirt-{$next/@name}.html"><img src="right.png" width="24" height="24" border="0" alt="Next"></img></a></td>
        </xsl:if>
      </tr>
    </table>
  </xsl:template>

  <!-- This is convoluted but needed to force the current document to
       be the API one and not the result tree from the tokenize() result,
       because the keys are only defined on the main document -->
  <xsl:template mode="dumptoken" match='*'>
    <xsl:param name="token"/>
    <xsl:variable name="stem" select="translate($token, '(),.:;@', '')"/>
    <xsl:variable name="ref" select="key('symbols', $stem)"/>
    <xsl:choose>
      <xsl:when test="$ref">
        <xsl:value-of select="substring-before($token, $stem)"/>
        <a href="libvirt-{$ref/@file}.html#{$ref/@name}"><xsl:value-of select="$stem"/></a>
        <xsl:value-of select="substring-after($token, $stem)"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="$token"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <!-- dumps a string, making cross-reference links -->
  <xsl:template name="dumptext">
    <xsl:param name="text"/>
    <xsl:variable name="ctxt" select='.'/>
    <!-- <xsl:value-of select="$text"/> -->
    <xsl:for-each select="str:tokenize($text, ' &#9;&#10;&#13;')">
      <xsl:apply-templates select="$ctxt" mode='dumptoken'>
        <xsl:with-param name="token" select="string(.)"/>
      </xsl:apply-templates>
      <xsl:if test="position() != last()">
        <xsl:text> </xsl:text>
      </xsl:if>
    </xsl:for-each>
  </xsl:template>

  <xsl:template match="macro" mode="toc">
    <xsl:text>#define </xsl:text>
    <a href="#{@name}"><xsl:value-of select="@name"/></a>
    <xsl:text>
</xsl:text>
  </xsl:template>

  <xsl:template match="variable" mode="toc">
    <xsl:call-template name="dumptext">
      <xsl:with-param name="text" select="string(@type)"/>
    </xsl:call-template>
    <xsl:text> </xsl:text>
    <a name="{@name}"></a>
    <xsl:value-of select="@name"/>
    <xsl:text>
</xsl:text>
  </xsl:template>

  <xsl:template match="typedef" mode="toc">
    <xsl:text>typedef </xsl:text><xsl:variable name="name" select="string(@name)"/>
    <xsl:choose>
      <xsl:when test="@type = 'enum'">
        <xsl:text>enum </xsl:text>
	<a href="#{$name}"><xsl:value-of select="$name"/></a>
	<xsl:text>
</xsl:text>
      </xsl:when>
      <xsl:otherwise>
	<xsl:call-template name="dumptext">
	  <xsl:with-param name="text" select="@type"/>
	</xsl:call-template>
	<xsl:text> </xsl:text>
	<a name="{$name}"><xsl:value-of select="$name"/></a>
	<xsl:text>
</xsl:text>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template match="typedef[@type = 'enum']">
    <xsl:variable name="name" select="string(@name)"/>
    <h3><a name="{$name}"><code><xsl:value-of select="$name"/></code></a></h3>
    <div class="api">
      <pre>
        <xsl:text>enum </xsl:text>
        <xsl:value-of select="$name"/>
        <xsl:text> {
</xsl:text>
      </pre>
      <table>
        <xsl:for-each select="/api/symbols/enum[@type = $name]">
          <xsl:sort select="@value" data-type="number" order="ascending"/>
          <tr>
            <td><a name="{@name}"><xsl:value-of select="@name"/></a></td>
            <td><xsl:text> = </xsl:text></td>
            <td><xsl:value-of select="@value"/></td>
            <xsl:if test="@info != ''">
              <td>
                <xsl:text> : </xsl:text>
                <xsl:call-template name="dumptext">
                  <xsl:with-param name="text" select="@info"/>
                </xsl:call-template>
              </td>
            </xsl:if>
          </tr>
        </xsl:for-each>
      </table>
      <pre>
        <xsl:text>}
</xsl:text>
      </pre>
    </div>
  </xsl:template>

  <xsl:template match="struct" mode="toc">
    <xsl:text>typedef </xsl:text>
    <xsl:value-of select="@type"/>
    <xsl:text> </xsl:text>
    <a href="#{@name}"><xsl:value-of select="@name"/></a>
    <xsl:text>
</xsl:text>
  </xsl:template>

  <xsl:template match="struct">
    <h3><a name="{@name}"><code><xsl:value-of select="@name"/></code></a></h3>
    <div class="api">
      <pre>
        <xsl:text>struct </xsl:text>
        <xsl:value-of select="@name"/>
        <xsl:text>{
</xsl:text>
      </pre>
      <table>
        <xsl:for-each select="field">
          <xsl:choose>
            <xsl:when test='@type = "union"'>
              <tr><td>union {</td></tr>
              <tr>
              <td><table>
              <xsl:for-each select="union/field">
                <tr>
                  <td>
                    <xsl:call-template name="dumptext">
                      <xsl:with-param name="text" select="@type"/>
                    </xsl:call-template>
                  </td>
                  <td><xsl:value-of select="@name"/></td>
                  <xsl:if test="@info != ''">
                    <td>
                      <xsl:text> : </xsl:text>
                      <xsl:call-template name="dumptext">
                        <xsl:with-param name="text" select="@info"/>
                      </xsl:call-template>
                    </td>
                  </xsl:if>
                </tr>
              </xsl:for-each>
              </table></td>
              <td></td></tr>
              <tr><td>}</td>
              <td><xsl:value-of select="@name"/></td>
                <xsl:if test="@info != ''">
                  <td>
                    <xsl:text> : </xsl:text>
                    <xsl:call-template name="dumptext">
                      <xsl:with-param name="text" select="@info"/>
                    </xsl:call-template>
                  </td>
                </xsl:if>
              <td></td></tr>
            </xsl:when>
            <xsl:otherwise>
              <tr>
                <td>
                  <xsl:call-template name="dumptext">
                    <xsl:with-param name="text" select="@type"/>
                  </xsl:call-template>
                </td>
                <td><xsl:value-of select="@name"/></td>
                <xsl:if test="@info != ''">
                  <td>
                    <xsl:text> : </xsl:text>
                    <xsl:call-template name="dumptext">
                      <xsl:with-param name="text" select="@info"/>
                    </xsl:call-template>
                  </td>
                </xsl:if>
              </tr>
            </xsl:otherwise>
          </xsl:choose>
        </xsl:for-each>
        <xsl:if test="not(field)">
          <tr>
            <td colspan="3">
              <xsl:text>The content of this structure is not made public by the API</xsl:text>
            </td>
          </tr>
        </xsl:if>
      </table>
      <pre>
        <xsl:text>
}
</xsl:text>
      </pre>
    </div>
  </xsl:template>

  <xsl:template match="macro">
    <xsl:variable name="name" select="string(@name)"/>
    <h3><a name="{$name}"><code><xsl:value-of select="$name"/></code></a></h3>
    <pre><xsl:text>#define </xsl:text><xsl:value-of select="$name"/></pre>
    <p>
    <xsl:call-template name="dumptext">
      <xsl:with-param name="text" select="info"/>
    </xsl:call-template>
    </p><xsl:text>
</xsl:text>
  </xsl:template>

  <xsl:template match="function" mode="toc">
    <xsl:variable name="name" select="string(@name)"/>
    <xsl:variable name="nlen" select="string-length($name)"/>
    <xsl:variable name="tlen" select="string-length(return/@type)"/>
    <xsl:variable name="blen" select="(($nlen + 8) - (($nlen + 8) mod 8)) + (($tlen + 8) - (($tlen + 8) mod 8))"/>
    <xsl:call-template name="dumptext">
      <xsl:with-param name="text" select="return/@type"/>
    </xsl:call-template>
    <xsl:text>&#9;</xsl:text>
    <a href="#{@name}"><xsl:value-of select="@name"/></a>
    <xsl:if test="$blen - 40 &lt; -8">
      <xsl:text>&#9;</xsl:text>
    </xsl:if>
    <xsl:if test="$blen - 40 &lt; 0">
      <xsl:text>&#9;</xsl:text>
    </xsl:if>
    <xsl:text>&#9;(</xsl:text>
    <xsl:if test="not(arg)">
      <xsl:text>void</xsl:text>
    </xsl:if>
    <xsl:for-each select="arg">
      <xsl:call-template name="dumptext">
        <xsl:with-param name="text" select="@type"/>
      </xsl:call-template>
      <xsl:text> </xsl:text>
      <xsl:value-of select="@name"/>
      <xsl:if test="position() != last()">
        <xsl:text>, </xsl:text><br/>
	<xsl:if test="$blen - 40 &gt; 8">
	  <xsl:text>&#9;</xsl:text>
	</xsl:if>
	<xsl:if test="$blen - 40 &gt; 0">
	  <xsl:text>&#9;</xsl:text>
	</xsl:if>
	<xsl:text>&#9;&#9;&#9;&#9;&#9; </xsl:text>
      </xsl:if>
    </xsl:for-each>
    <xsl:text>)
</xsl:text>
  </xsl:template>

  <xsl:template match="functype" mode="toc">
    <xsl:variable name="name" select="string(@name)"/>
    <xsl:variable name="nlen" select="string-length($name)"/>
    <xsl:variable name="tlen" select="string-length(return/@type)"/>
    <xsl:variable name="blen" select="(($nlen + 8) - (($nlen + 8) mod 8)) + (($tlen + 8) - (($tlen + 8) mod 8))"/>
    <xsl:text>typedef </xsl:text>
    <a href="#{$name}"><xsl:value-of select="$name"/></a>
    <xsl:text>
</xsl:text>
    <xsl:call-template name="dumptext">
      <xsl:with-param name="text" select="return/@type"/>
    </xsl:call-template>
    <xsl:text>&#9;</xsl:text>
    <a href="#{$name}"><xsl:value-of select="$name"/></a>
    <xsl:if test="$blen - 40 &lt; -8">
      <xsl:text>&#9;</xsl:text>
    </xsl:if>
    <xsl:if test="$blen - 40 &lt; 0">
      <xsl:text>&#9;</xsl:text>
    </xsl:if>
    <xsl:text>&#9;(</xsl:text>
    <xsl:if test="not(arg)">
      <xsl:text>void</xsl:text>
    </xsl:if>
    <xsl:for-each select="arg">
      <xsl:call-template name="dumptext">
        <xsl:with-param name="text" select="@type"/>
      </xsl:call-template>
      <xsl:text> </xsl:text>
      <xsl:value-of select="@name"/>
      <xsl:if test="position() != last()">
        <xsl:text>, </xsl:text><br/>
	<xsl:if test="$blen - 40 &gt; 8">
	  <xsl:text>&#9;</xsl:text>
	</xsl:if>
	<xsl:if test="$blen - 40 &gt; 0">
	  <xsl:text>&#9;</xsl:text>
	</xsl:if>
	<xsl:text>&#9;&#9;&#9;&#9;&#9; </xsl:text>
      </xsl:if>
    </xsl:for-each>
    <xsl:text>)
</xsl:text>
    <xsl:text>
</xsl:text>
  </xsl:template>

  <xsl:template match="functype">
    <xsl:variable name="name" select="string(@name)"/>
    <xsl:variable name="nlen" select="string-length($name)"/>
    <xsl:variable name="tlen" select="string-length(return/@type)"/>
    <xsl:variable name="blen" select="(($nlen + 8) - (($nlen + 8) mod 8)) + (($tlen + 8) - (($tlen + 8) mod 8))"/>
    <h3><a name="{$name}"><code><xsl:value-of select="$name"/></code></a></h3>
    <pre class="programlisting">
    <xsl:text>typedef </xsl:text>
    <xsl:call-template name="dumptext">
      <xsl:with-param name="text" select="return/@type"/>
    </xsl:call-template>
    <xsl:text>&#9;(*</xsl:text>
    <xsl:value-of select="@name"/>
    <xsl:if test="$blen - 40 &lt; -8">
      <xsl:text>&#9;</xsl:text>
    </xsl:if>
    <xsl:if test="$blen - 40 &lt; 0">
      <xsl:text>&#9;</xsl:text>
    </xsl:if>
    <xsl:text>)&#9;(</xsl:text>
    <xsl:if test="not(arg)">
      <xsl:text>void</xsl:text>
    </xsl:if>
    <xsl:for-each select="arg">
      <xsl:call-template name="dumptext">
        <xsl:with-param name="text" select="@type"/>
      </xsl:call-template>
      <xsl:text> </xsl:text>
      <xsl:value-of select="@name"/>
      <xsl:if test="position() != last()">
        <xsl:text>, </xsl:text><br/>
	<xsl:if test="$blen - 40 &gt; 8">
	  <xsl:text>&#9;</xsl:text>
	</xsl:if>
	<xsl:if test="$blen - 40 &gt; 0">
	  <xsl:text>&#9;</xsl:text>
	</xsl:if>
	<xsl:text>&#9;&#9;&#9;&#9;&#9; </xsl:text>
      </xsl:if>
    </xsl:for-each>
    <xsl:text>)
</xsl:text>
    </pre>
    <p>
    <xsl:call-template name="dumptext">
      <xsl:with-param name="text" select="info"/>
    </xsl:call-template>
    </p>
    <xsl:if test="arg | return">
      <div class="variablelist"><table border="0"><col align="left"/><tbody>
      <xsl:for-each select="arg">
        <tr>
          <td><span class="term"><i><tt><xsl:value-of select="@name"/></tt></i>:</span></td>
	  <td>
	    <xsl:call-template name="dumptext">
	      <xsl:with-param name="text" select="@info"/>
	    </xsl:call-template>
	  </td>
        </tr>
      </xsl:for-each>
      <xsl:if test="return/@info">
        <tr>
          <td><span class="term"><i><tt>Returns</tt></i>:</span></td>
	  <td>
	    <xsl:call-template name="dumptext">
	      <xsl:with-param name="text" select="return/@info"/>
	    </xsl:call-template>
	  </td>
        </tr>
      </xsl:if>
      </tbody></table></div>
    </xsl:if>
    <br/>
    <xsl:text>
</xsl:text>
  </xsl:template>

  <xsl:template match="function">
    <xsl:variable name="name" select="string(@name)"/>
    <xsl:variable name="nlen" select="string-length($name)"/>
    <xsl:variable name="tlen" select="string-length(return/@type)"/>
    <xsl:variable name="blen" select="(($nlen + 8) - (($nlen + 8) mod 8)) + (($tlen + 8) - (($tlen + 8) mod 8))"/>
    <h3><a name="{$name}"><code><xsl:value-of select="$name"/></code></a></h3>
    <pre class="programlisting">
    <xsl:call-template name="dumptext">
      <xsl:with-param name="text" select="return/@type"/>
    </xsl:call-template>
    <xsl:text>&#9;</xsl:text>
    <xsl:value-of select="@name"/>
    <xsl:if test="$blen - 40 &lt; -8">
      <xsl:text>&#9;</xsl:text>
    </xsl:if>
    <xsl:if test="$blen - 40 &lt; 0">
      <xsl:text>&#9;</xsl:text>
    </xsl:if>
    <xsl:text>&#9;(</xsl:text>
    <xsl:if test="not(arg)">
      <xsl:text>void</xsl:text>
    </xsl:if>
    <xsl:for-each select="arg">
      <xsl:call-template name="dumptext">
        <xsl:with-param name="text" select="@type"/>
      </xsl:call-template>
      <xsl:text> </xsl:text>
      <xsl:value-of select="@name"/>
      <xsl:if test="position() != last()">
        <xsl:text>, </xsl:text><br/>
	<xsl:if test="$blen - 40 &gt; 8">
	  <xsl:text>&#9;</xsl:text>
	</xsl:if>
	<xsl:if test="$blen - 40 &gt; 0">
	  <xsl:text>&#9;</xsl:text>
	</xsl:if>
	<xsl:text>&#9;&#9;&#9;&#9;&#9; </xsl:text>
      </xsl:if>
    </xsl:for-each>
    <xsl:text>)</xsl:text><br/>
    <xsl:text>
</xsl:text>
    </pre>
    <p>
    <xsl:call-template name="dumptext">
      <xsl:with-param name="text" select="info"/>
    </xsl:call-template>
    </p><xsl:text>
</xsl:text>
    <xsl:if test="arg | return/@info">
      <div class="variablelist"><table border="0"><col align="left"/><tbody>
      <xsl:for-each select="arg">
        <tr>
          <td><span class="term"><i><tt><xsl:value-of select="@name"/></tt></i>:</span></td>
	  <td>
	    <xsl:call-template name="dumptext">
	      <xsl:with-param name="text" select="@info"/>
	    </xsl:call-template>
	  </td>
        </tr>
      </xsl:for-each>
      <xsl:if test="return/@info">
        <tr>
          <td><span class="term"><i><tt>Returns</tt></i>:</span></td>
	  <td>
	    <xsl:call-template name="dumptext">
	      <xsl:with-param name="text" select="return/@info"/>
	    </xsl:call-template>
	  </td>
        </tr>
      </xsl:if>
      </tbody></table></div>
    </xsl:if>
  </xsl:template>

  <xsl:template match="exports" mode="toc">
    <xsl:apply-templates select="key('symbols', string(@symbol))[1]" mode="toc"/>
  </xsl:template>

  <xsl:template match="exports">
    <xsl:apply-templates select="key('symbols', string(@symbol))[1]"/>
  </xsl:template>

  <xsl:template name="description">
    <xsl:if test="deprecated">
      <h2 style="font-weight:bold;color:red;text-align:center">This module is deprecated</h2>
    </xsl:if>
    <xsl:if test="description">
      <p><xsl:value-of select="description"/></p>
    </xsl:if>
  </xsl:template>

  <xsl:template name="docomponents">
    <xsl:apply-templates select="exports[@type='macro']">
      <xsl:sort select='@symbol'/>
    </xsl:apply-templates>
    <xsl:apply-templates select="exports[@type='enum']">
      <xsl:sort select='@symbol'/>
    </xsl:apply-templates>
    <xsl:apply-templates select="exports[@type='typedef']">
      <xsl:sort select='@symbol'/>
    </xsl:apply-templates>
    <xsl:apply-templates select="exports[@type='struct']">
      <xsl:sort select='@symbol'/>
    </xsl:apply-templates>
    <xsl:apply-templates select="exports[@type='function']">
      <xsl:sort select='@symbol'/>
    </xsl:apply-templates>
  </xsl:template>

  <xsl:template match="file">
    <xsl:variable name="name" select="@name"/>
    <xsl:variable name="title">Module <xsl:value-of select="$name"/> from <xsl:value-of select="/api/@name"/></xsl:variable>
    <html>
      <body>
        <h1><xsl:value-of select="$title"/></h1>
        <xsl:call-template name="description"/>
        <h2>Table of Contents</h2>
        <xsl:if test="count(exports[@type='macro']) > 0">
          <h3><a href="#macros">Macros</a></h3>
          <pre>
            <xsl:apply-templates select="exports[@type='macro']" mode="toc">
              <xsl:sort select='@symbol'/>
            </xsl:apply-templates>
          </pre>
        </xsl:if>
        <h3><a href="#types">Types</a></h3>
        <pre>
          <xsl:apply-templates select="exports[@type='typedef']" mode="toc">
            <xsl:sort select='@symbol'/>
          </xsl:apply-templates>
        </pre>
        <h3><a href="#functions">Functions</a></h3>
        <pre>
          <xsl:apply-templates select="exports[@type='function']" mode="toc">
            <xsl:sort select='@symbol'/>
          </xsl:apply-templates>
        </pre>

        <h2>Description</h2>

        <xsl:if test="count(exports[@type='macro']) > 0">
          <h3><a name="macros">Macros</a></h3>
          <xsl:apply-templates select="exports[@type='macro']">
            <xsl:sort select='@symbol'/>
          </xsl:apply-templates>
        </xsl:if>
        <h3><a name="types">Types</a></h3>
        <xsl:apply-templates select="exports[@type='typedef']">
          <xsl:sort select='@symbol'/>
        </xsl:apply-templates>
        <h3><a name="functions">Functions</a></h3>
        <xsl:apply-templates select="exports[@type='function']">
          <xsl:sort select='@symbol'/>
        </xsl:apply-templates>
      </body>
    </html>
  </xsl:template>

  <xsl:template match="file" mode="toc">
    <xsl:variable name="name" select="@name"/>
    <li>
      <a href="libvirt-{$name}.html"><xsl:value-of select="$name"/></a>
      <xsl:text>: </xsl:text>
      <xsl:value-of select="summary"/>
    </li>
  </xsl:template>

  <xsl:template name="mainpage">
    <xsl:variable name="title">Reference Manual for <xsl:value-of select="/api/@name"/></xsl:variable>
    <html>
      <body>
        <h1><xsl:value-of select="$title"/></h1>
        <h2>Table of Contents</h2>
        <ul>
          <xsl:apply-templates select="/api/files/file" mode="toc"/>
        </ul>
      </body>
    </html>
  </xsl:template>

  <xsl:template match="/">
    <!-- Save the main index.html as well as a couple of copies -->
    <xsl:variable name="mainpage">
      <xsl:call-template name="mainpage"/>
    </xsl:variable>
    <xsl:document
      href="{concat($htmldir, '/index.html')}"
      method="xml"
      encoding="UTF-8"
      doctype-public="-//W3C//DTD XHTML 1.0 Transitional//EN"
      doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
      <xsl:apply-templates select="exsl:node-set($mainpage)" mode="page">
        <xsl:with-param name="pagename" select="concat($htmldir, '/index.html')"/>
      </xsl:apply-templates>
    </xsl:document>

    <xsl:for-each select="/api/files/file">
      <xsl:variable name="subpage">
        <xsl:apply-templates select="."/>
      </xsl:variable>

      <xsl:document
        href="{concat($htmldir, '/libvirt-', @name, '.html')}"
        method="xml"
        encoding="UTF-8"
        doctype-public="-//W3C//DTD XHTML 1.0 Transitional//EN"
        doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
        <xsl:apply-templates select="exsl:node-set($subpage)" mode="page">
          <xsl:with-param name="pagename" select="concat($htmldir, '/libvirt-', @name, '.html')"/>
        </xsl:apply-templates>
      </xsl:document>
    </xsl:for-each>
  </xsl:template>

</xsl:stylesheet>
