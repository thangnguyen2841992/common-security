package com.nihongo.security;
import org.junit.jupiter.api.Test;import java.util.*;import java.nio.charset.StandardCharsets;import static org.junit.jupiter.api.Assertions.*;
class SafeCsvTest {
 @Test void escapesQuotesAndFormulaCellsAndPreservesNumbers(){String csv=new String(SafeCsv.write(List.of("Tên","Tiền"),List.of(Arrays.asList("=HYPERLINK(\"evil\")",-100),Arrays.asList("Người, học\nN3",null),Arrays.asList(" \t+cmd","@SUM(A1)"))),StandardCharsets.UTF_8);assertTrue(csv.startsWith("\ufeff"));assertTrue(csv.contains("'"+"=HYPERLINK("));assertTrue(csv.contains("\"-100\""));assertTrue(csv.contains("\"Người, học\nN3\""));assertTrue(csv.contains("' \t+cmd"));assertTrue(csv.contains("'@SUM(A1)"));}
 @Test void limitsExportSize(){assertThrows(IllegalArgumentException.class,()->SafeCsv.write(List.of("Data"),Collections.nCopies(10001,List.of("value"))));}
}
