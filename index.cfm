<cfscript>

	// This is the untrusted HTML input that we need to sanitize.
	```
	<cfsavecontent variable="htmlInput">

		<p>
			Check out
			<a href="https://www.bennadel.com" onmousedown="alert( 'XSS!' )">my site</a>.
		</p>

		<marquee loop="-1" width="100%">
			I am very trustable! You can totes trust me!
		</marquee>

		<p>
			<strong>Thanks for stopping by!</strong> <em>You Rock!</em> &amp;
			<blink>Woot!</blink>
		</p>

	</cfsavecontent>
	```

	// ------------------------------------------------------------------------------- //
	// ------------------------------------------------------------------------------- //

	Pattern = createObject( "java", "java.util.regex.Pattern" );

	// The Policy Builder has a number of fluent APIs that allow us to incrementally
	// define the sanitization policy. It primarily consists of allow-listing elements
	// and attributes (usually in the context of a given set of elements).
	policyBuilder = javaNew( "org.owasp.html.HtmlPolicyBuilder" )
		.init()
		.allowElements([
			"p", "div",
			"br",
			"a",
			"b", "strong",
			"i", "em",
			"ul", "ol", "li"
		])
		.allowUrlProtocols([ "http", "https" ])
		.requireRelNofollowOnLinks()
		.allowAttributes([ "title" ])
			.globally()
		.allowAttributes([ "href", "target" ])
			.onElements([ "a" ])
		.allowAttributes([ "lang" ])
			.matching( Pattern.compile( "[a-zA-Z]{2,20}" ) )
			.globally()
		.allowAttributes([ "align" ])
			// NOTE: true = ignoreCase.
			.matching( true, [ "center", "left", "right", "justify" ] )
			.onElements([ "p" ])
	;
	policy = policyBuilder.toFactory();

	// Sanitize the HTML input.
	// --
	// NOTE: There's a more complicated invocation of the sanitization that allows you to
	// capture the block-listed elements and attributes that are removed from input. That
	// said, I could NOT FIGURE OUT how to do that - it looks like you might need to
	// write some actual Java code to provide the necessary arguments.
	sanitizedHtmlInput = policy.sanitize( htmlInput );

	// ------------------------------------------------------------------------------- //
	// ------------------------------------------------------------------------------- //

	```
	<h1>
		OWASP Java Html Sanitizer
	</h1>

	<h2>
		Untrusted Input
	</h2>

	<cfoutput>
		<!--- NOTE: I'm dedenting the indentation incurred by the CFSaveContent tag. --->
		<pre>#encodeForHtml( htmlInput.reReplace( "(?m)^\t\t", "", "all" ).trim() )#</pre>
	</cfoutput>

	<h2>
		Sanitized Input
	</h2>

	<cfoutput>
		<!--- NOTE: I'm dedenting the indentation incurred by the CFSaveContent tag. --->
		<pre>#encodeForHtml( sanitizedHtmlInput.reReplace( "(?m)^\t\t", "", "all" ).trim() )#</pre>
	</cfoutput>
	```

	// ------------------------------------------------------------------------------- //
	// ------------------------------------------------------------------------------- //

	/**
	* I load the given Java class using the underlying JAR files.
	*/
	public any function javaNew( required string className ) {

		// I downloaded these from the Maven Repository (manually since I don't actually
		// know how Maven works).
		// --
		// https://mvnrepository.com/artifact/com.googlecode.owasp-java-html-sanitizer/owasp-java-html-sanitizer/20200713.1
		var jarFiles = [
			"./vendor/owasp-java-html-sanitizer-20200713.1/animal-sniffer-annotations-1.17.jar",
			"./vendor/owasp-java-html-sanitizer-20200713.1/checker-qual-2.5.2.jar",
			"./vendor/owasp-java-html-sanitizer-20200713.1/error_prone_annotations-2.2.0.jar",
			"./vendor/owasp-java-html-sanitizer-20200713.1/failureaccess-1.0.1.jar",
			"./vendor/owasp-java-html-sanitizer-20200713.1/guava-27.1-jre.jar",
			"./vendor/owasp-java-html-sanitizer-20200713.1/j2objc-annotations-1.1.jar",
			"./vendor/owasp-java-html-sanitizer-20200713.1/jsr305-3.0.2.jar",
			"./vendor/owasp-java-html-sanitizer-20200713.1/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar",
			"./vendor/owasp-java-html-sanitizer-20200713.1/owasp-java-html-sanitizer-20200713.1.jar"
		];

		return( createObject( "java", className, jarFiles ) );

	}

</cfscript>
