package com.nihongo.security;
import java.nio.charset.StandardCharsets;import java.util.*;
public final class SafeCsv {
 private SafeCsv(){}
 public static byte[] write(List<String> header,List<? extends List<?>> rows){if(rows.size()>10000)throw new IllegalArgumentException("CSV export supports at most 10000 rows");StringBuilder output=new StringBuilder("\ufeff");row(output,header);for(var values:rows)row(output,values);return output.toString().getBytes(StandardCharsets.UTF_8);}
 private static void row(StringBuilder output,List<?> values){for(int i=0;i<values.size();i++){if(i>0)output.append(',');Object value=values.get(i);String text=value==null?"":value.toString();if(!(value instanceof Number)&&text.matches("(?s)^[\\s\\p{Z}]*[=+@-].*"))text="'"+text;output.append('"').append(text.replace("\"","\"\"")).append('"');}output.append("\r\n");}
}
