<?php

class GrokTest extends \PHPUnit_Framework_TestCase
{
    public function testShouldParseQuotedString()
    {
        $expectedResult = '"quoted string parsed"';
        $grokParser = new Grok;

        $result = $grokParser->parse('%{QS:result}', '"quoted string parsed"');
        $this->assertEquals($expectedResult, $result['result']);
    }
}
