<?xml version="1.0"?>
<!--
  Stylesheet to generate the HTML documentation from an XML API descriptions:
  xsltproc newapi.xsl libvirt-api.xml

  Daniel Veillard
-->
<xsl:stylesheet version="1.0"
  xmlns="http://www.w3.org/1999/xhtml"
  xmlns:html="http://www.w3.org/1999/xhtml"
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

  <xsl:param name="builddir" select="'..'"/>

  <!-- the target directory for the HTML output -->
  <xsl:variable name="htmldir">html</xsl:variable>
  <xsl:variable name="href_base">../</xsl:variable>

  <xsl:variable name="acls">
    <xsl:copy-of select="document('{$builddir}/src/libvirt_access.xml')/aclinfo/api"/>
  </xsl:variable>
  <xsl:variable name="qemuacls">
    <xsl:copy-of select="document('{$builddir}/src/libvirt_access_qemu.xml')/aclinfo/api"/>
  </xsl:variable>
  <xsl:variable name="lxcacls">
    <xsl:copy-of select="document('{$builddir}/src/libvirt_access_lxc.xml')/aclinfo/api"/>
  </xsl:variable>

  <xsl:template name="aclinfo">
    <xsl:param name="api"/>

    <xsl:if test="count(exsl:node-set($acls)/api[@name=$api]/check) > 0">
      <h5>Access control parameter checks</h5>
      <table class="acl">
        <thead>
          <tr>
            <th>Object</th>
            <th>Permission</th>
            <th>Condition</th>
          </tr>
        </thead>
        <xsl:apply-templates select="exsl:node-set($acls)/api[@name=$api]/check" mode="acl"/>
      </table>
    </xsl:if>
    <xsl:if test="count(exsl:node-set($acls)/api[@name=$api]/filter) > 0">
      <h5>Access control return value filters</h5>
      <table class="acl">
        <thead>
          <tr>
            <th>Object</th>
            <th>Permission</th>
          </tr>
        </thead>
        <xsl:apply-templates select="exsl:node-set($acls)/api[@name=$api]/filter" mode="acl"/>
      </table>
    </xsl:if>
  </xsl:template>

  <xsl:template match="check" mode="acl">
    <tr>
      <td><a href="../acl.html#object_{@object}"><xsl:value-of select="@object"/></a></td>
      <td><a href="../acl.html#perm_{@object}_{@perm}"><xsl:value-of select="@perm"/></a></td>
      <xsl:choose>
        <xsl:when test="@flags">
          <td><xsl:value-of select="@flags"/></td>
        </xsl:when>
        <xsl:otherwise>
          <td>-</td>
        </xsl:otherwise>
      </xsl:choose>
    </tr>
  </xsl:template>

  <xsl:template match="filter" mode="acl">
    <tr>
      <td><xsl:value-of select="@object"/></td>
      <td><xsl:value-of select="@perm"/></td>
    </tr>
  </xsl:template>


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
      <xsl:when test="starts-with($token, 'http://')">
        <a href="{$token}">
          <xsl:value-of select="$token"/>
        </a>
      </xsl:when>
      <xsl:when test="starts-with($token, '&lt;http://') and contains($token, '&gt;')">
        <xsl:variable name="link"
                      select="substring(substring-before($token, '&gt;'), 2)"/>
        <a href="{$link}">
          <xsl:value-of select="$link"/>
        </a>
        <xsl:value-of select="substring-after($token, '&gt;')"/>
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


  <!-- process blocks of text. blocks are separated by two consecutive line -->
  <!-- breaks.                                                              -->
  <!--                                                                      -->
  <!-- blocks indented with at least 2 spaces are considered code blocks.   -->
  <!--                                                                      -->
  <!-- consecutive code blocks are collapsed into a single code block.      -->
  <xsl:template name="formatblock">
    <xsl:param name="block"/>
    <xsl:param name="rest"/>

    <xsl:variable name="multipleCodeBlocks"
                  select="starts-with($block, '  ') and starts-with($rest, '  ')"/>

    <xsl:choose>
      <xsl:when test="$multipleCodeBlocks">
        <xsl:call-template name="formatblock">
          <xsl:with-param name="block">
            <xsl:choose>
              <xsl:when test="contains($rest, '&#xA;&#xA;')">
                <xsl:value-of select="concat($block, '&#xA;  &#xA;',
                                        substring-before($rest, '&#xA;&#xA;'))" />
              </xsl:when>
              <xsl:otherwise>
                <xsl:value-of select="concat($block, '&#xA;  &#xA;', $rest)" />
              </xsl:otherwise>
            </xsl:choose>
          </xsl:with-param>
          <xsl:with-param name="rest" select="substring-after($rest, '&#xA;&#xA;')"/>
        </xsl:call-template>
      </xsl:when>
      <xsl:when test="starts-with($block, '  ')">
        <pre class="code"><xsl:for-each select="str:tokenize($block, '&#xA;')">
          <xsl:choose>
            <xsl:when test="starts-with(., '  ')">
              <xsl:value-of select="substring(., 3)"/>
            </xsl:when>
            <xsl:otherwise>
              <xsl:value-of select="."/>
            </xsl:otherwise>
          </xsl:choose>
          <xsl:if test="position() != last()">
            <xsl:text>&#xA;</xsl:text>
          </xsl:if>
        </xsl:for-each></pre>
      </xsl:when>
      <xsl:otherwise>
        <p>
          <xsl:call-template name="dumptext">
            <xsl:with-param name="text" select="$block"/>
          </xsl:call-template>
        </p>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:if test="not($multipleCodeBlocks)">
      <xsl:call-template name="formattext">
        <xsl:with-param name="text" select="$rest"/>
      </xsl:call-template>
    </xsl:if>
  </xsl:template>

  <xsl:template name="formattext">
    <xsl:param name="text" />

    <xsl:if test="$text">
      <xsl:variable name="head" select="substring-before($text, '&#xA;&#xA;')"/>
      <xsl:variable name="rest" select="substring-after($text, '&#xA;&#xA;')"/>

      <xsl:call-template name="formatblock">
        <xsl:with-param name="block">
          <xsl:choose>
            <xsl:when test="contains($text, '&#xA;&#xA;')">
              <xsl:value-of select="$head"/>
            </xsl:when>
            <xsl:otherwise>
              <xsl:value-of select="$text"/>
            </xsl:otherwise>
          </xsl:choose>
        </xsl:with-param>
        <xsl:with-param name="rest" select="$rest"/>
      </xsl:call-template>
    </xsl:if>
  </xsl:template>

  <xsl:template match="macro" mode="toc">
    <span class="directive">#define</span><xsl:text> </xsl:text>
    <a href="#{@name}"><xsl:value-of select="@name"/></a>
    <xsl:text>
</xsl:text>
  </xsl:template>

  <xsl:template match="variable" mode="toc">
    <span class="type">
      <xsl:call-template name="dumptext">
        <xsl:with-param name="text" select="string(@type)"/>
      </xsl:call-template>
    </span>
    <xsl:text> </xsl:text>
    <a name="{@name}"></a>
    <xsl:value-of select="@name"/>
    <xsl:text>
</xsl:text>
  </xsl:template>

  <xsl:template match="typedef" mode="toc">
    <span class="keyword">typedef</span>
    <xsl:text> </xsl:text><xsl:variable name="name" select="string(@name)"/>
    <xsl:choose>
      <xsl:when test="@type = 'enum'">
        <span class="keyword">enum</span><xsl:text> </xsl:text>
	<a href="#{$name}"><xsl:value-of select="$name"/></a>
	<xsl:text>
</xsl:text>
      </xsl:when>
      <xsl:otherwise>
	<span class="type">
          <xsl:call-template name="dumptext">
            <xsl:with-param name="text" select="@type"/>
          </xsl:call-template>
        </span>
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
        <span class="keyword">enum</span><xsl:text> </xsl:text>
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
            <xsl:choose>
              <xsl:when test="@info != ''">
                <td><xsl:value-of select="@value"/></td>
                <td>
                  <div class="comment">
                    <xsl:call-template name="dumptext">
                      <xsl:with-param name="text" select="@info"/>
                    </xsl:call-template>
                  </div>
                </td>
              </xsl:when>
              <xsl:otherwise>
                <td colspan="2"><xsl:value-of select="@value"/></td>
              </xsl:otherwise>
            </xsl:choose>
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
    <span class="keyword">typedef</span><xsl:text> </xsl:text>
    <span class="type"><xsl:value-of select="@type"/></span>
    <xsl:text> </xsl:text>
    <a href="#{@name}"><xsl:value-of select="@name"/></a>
    <xsl:text>
</xsl:text>
  </xsl:template>

  <xsl:template match="struct">
    <h3><a name="{@name}"><code><xsl:value-of select="@name"/></code></a></h3>
    <div class="api">
      <pre>
        <span class="keyword">struct </span>
        <xsl:value-of select="@name"/>
        <xsl:text> {
</xsl:text>
      </pre>
      <xsl:if test="field">
        <table>
          <xsl:for-each select="field">
            <xsl:choose>
              <xsl:when test='@type = "union"'>
                <tr><td><span class="keyword">union</span> {</td></tr>
                <tr>
                  <td><table>
                    <xsl:for-each select="union/field">
                      <tr>
                        <td>
                          <span class="type">
                            <xsl:call-template name="dumptext">
                              <xsl:with-param name="text" select="@type"/>
                            </xsl:call-template>
                          </span>
                        </td>
                        <td><xsl:value-of select="@name"/></td>
                        <xsl:if test="@info != ''">
                          <td>
                            <div class="comment">
                              <xsl:call-template name="dumptext">
                                <xsl:with-param name="text" select="@info"/>
                              </xsl:call-template>
                            </div>
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
                    <div class="comment">
                      <xsl:call-template name="dumptext">
                        <xsl:with-param name="text" select="@info"/>
                      </xsl:call-template>
                    </div>
                  </td>
                </xsl:if>
                <td></td></tr>
              </xsl:when>
              <xsl:otherwise>
                <tr>
                  <td>
                    <span class="type">
                      <xsl:call-template name="dumptext">
                        <xsl:with-param name="text" select="@type"/>
                      </xsl:call-template>
                    </span>
                  </td>
                  <td><xsl:value-of select="@name"/></td>
                  <xsl:if test="@info != ''">
                    <td>
                      <div class="comment">
                        <xsl:call-template name="dumptext">
                        <xsl:with-param name="text" select="@info"/>
                        </xsl:call-template>
                      </div>
                    </td>
                  </xsl:if>
                </tr>
              </xsl:otherwise>
            </xsl:choose>
          </xsl:for-each>
        </table>
      </xsl:if>
      <xsl:if test="not(field)">
        <div class="undisclosed">The content of this structure is not made public by the API</div>
      </xsl:if>
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
    <pre class="api"><span class="directive">#define</span><xsl:text> </xsl:text><xsl:value-of select="$name"/></pre>
    <div class="description">
    <xsl:call-template name="formattext">
      <xsl:with-param name="text" select="info"/>
    </xsl:call-template>
    </div><xsl:text>
</xsl:text>
  </xsl:template>

  <xsl:template match="function" mode="toc">
    <xsl:variable name="name" select="string(@name)"/>
    <xsl:variable name="nlen" select="string-length($name)"/>
    <xsl:variable name="tlen" select="string-length(return/@type)"/>
    <xsl:variable name="blen" select="(($nlen + 8) - (($nlen + 8) mod 8)) + (($tlen + 8) - (($tlen + 8) mod 8))"/>
    <span class="type">
      <xsl:call-template name="dumptext">
        <xsl:with-param name="text" select="return/@type"/>
      </xsl:call-template>
    </span>
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
      <span class="type">void</span>
    </xsl:if>
    <xsl:for-each select="arg">
      <span class="type">
        <xsl:call-template name="dumptext">
          <xsl:with-param name="text" select="@type"/>
        </xsl:call-template>
      </span>
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
    <span class="keyword">typedef</span><xsl:text> </xsl:text>
    <a href="#{$name}"><xsl:value-of select="$name"/></a>
    <xsl:text>
</xsl:text>
    <span class="type">
      <xsl:call-template name="dumptext">
        <xsl:with-param name="text" select="return/@type"/>
      </xsl:call-template>
    </span>
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
      <span class="type">void</span>
    </xsl:if>
    <xsl:for-each select="arg">
      <span class="type">
        <xsl:call-template name="dumptext">
          <xsl:with-param name="text" select="@type"/>
        </xsl:call-template>
      </span>
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
    <pre class="api">
    <span class="keyword">typedef</span><xsl:text> </xsl:text>
    <span class="type">
      <xsl:call-template name="dumptext">
        <xsl:with-param name="text" select="return/@type"/>
      </xsl:call-template>
    </span>
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
      <span class="type">void</span>
    </xsl:if>
    <xsl:for-each select="arg">
      <span class="type">
        <xsl:call-template name="dumptext">
          <xsl:with-param name="text" select="@type"/>
        </xsl:call-template>
      </span>
      <xsl:text> </xsl:text>
      <xsl:value-of select="@name"/>
      <xsl:if test="position() != last()">
        <xsl:text>,
</xsl:text>
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
    <div class="description">
    <xsl:call-template name="formattext">
      <xsl:with-param name="text" select="info"/>
    </xsl:call-template>
    </div>
    <xsl:if test="arg | return">
      <dl class="variablelist">
      <xsl:for-each select="arg">
        <dt><xsl:value-of select="@name"/></dt>
        <dd>
          <xsl:call-template name="dumptext">
	      <xsl:with-param name="text" select="@info"/>
	    </xsl:call-template>
        </dd>
      </xsl:for-each>
      <xsl:if test="return/@info">
        <dt>Returns</dt>
        <dd>
          <xsl:call-template name="dumptext">
            <xsl:with-param name="text" select="return/@info"/>
          </xsl:call-template>
        </dd>
      </xsl:if>
      </dl>
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
    <pre class="api">
    <span class="type">
      <xsl:call-template name="dumptext">
        <xsl:with-param name="text" select="return/@type"/>
      </xsl:call-template>
    </span>
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
      <span class="type">void</span>
    </xsl:if>
    <xsl:for-each select="arg">
      <span class="type">
        <xsl:call-template name="dumptext">
          <xsl:with-param name="text" select="@type"/>
        </xsl:call-template>
      </span>
      <xsl:text> </xsl:text>
      <xsl:value-of select="@name"/>
      <xsl:if test="position() != last()">
        <xsl:text>,
</xsl:text>
	<xsl:if test="$blen - 40 &gt; 8">
	  <xsl:text>&#9;</xsl:text>
	</xsl:if>
	<xsl:if test="$blen - 40 &gt; 0">
	  <xsl:text>&#9;</xsl:text>
	</xsl:if>
	<xsl:text>&#9;&#9;&#9;&#9;&#9; </xsl:text>
      </xsl:if>
    </xsl:for-each>
    <xsl:text>)</xsl:text>
    </pre>
    <div class="description">
    <xsl:call-template name="formattext">
      <xsl:with-param name="text" select="info"/>
    </xsl:call-template>
    </div><xsl:text>
</xsl:text>
    <xsl:if test="arg | return/@info">
      <dl class="variablelist">
        <xsl:for-each select="arg">
          <dt><xsl:value-of select="@name"/></dt>
          <dd>
            <xsl:call-template name="dumptext">
              <xsl:with-param name="text" select="@info"/>
            </xsl:call-template>
          </dd>
        </xsl:for-each>
        <xsl:if test="return/@info">
          <dt>Returns</dt>
          <dd>
	    <xsl:call-template name="dumptext">
	      <xsl:with-param name="text" select="return/@info"/>
	    </xsl:call-template>
          </dd>
        </xsl:if>
      </dl>
    </xsl:if>
    <div class="acl">
      <xsl:call-template name="aclinfo">
        <xsl:with-param name="api" select="$name"/>
      </xsl:call-template>
    </div>
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
      <p>
        <xsl:call-template name="dumptext">
          <xsl:with-param name="text" select="description"/>
        </xsl:call-template>
      </p>
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
          <pre class="api">
            <xsl:apply-templates select="exports[@type='macro']" mode="toc">
              <xsl:sort select='@symbol'/>
            </xsl:apply-templates>
          </pre>
        </xsl:if>
        <h3><a href="#types">Types</a></h3>
        <pre class="api">
          <xsl:apply-templates select="exports[@type='typedef']" mode="toc">
            <xsl:sort select='@symbol'/>
          </xsl:apply-templates>
        </pre>
        <h3><a href="#functions">Functions</a></h3>
        <pre class="api">
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
        <xsl:with-param name="timestamp" select="$timestamp"/>
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
          <xsl:with-param name="timestamp" select="$timestamp"/>
        </xsl:apply-templates>
      </xsl:document>
    </xsl:for-each>
  </xsl:template>

</xsl:stylesheet>
