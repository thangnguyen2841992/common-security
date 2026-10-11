package com.nihongo.security;
import java.time.*;
public record CsvDates(LocalDate from,LocalDate to) {
 public static CsvDates validate(LocalDate from,LocalDate to){var end=to==null?LocalDate.now():to;var begin=from==null?end.minusDays(29):from;if(end.isBefore(begin)||java.time.temporal.ChronoUnit.DAYS.between(begin,end)>365)throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.BAD_REQUEST,"Chọn khoảng xuất tối đa 366 ngày");return new CsvDates(begin,end);}
}
