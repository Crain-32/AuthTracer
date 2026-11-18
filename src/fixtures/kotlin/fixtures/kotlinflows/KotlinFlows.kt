package fixtures.kotlinflows

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

data class Report(val title: String)

/**
 * A Kotlin Flow is written as many of its elements; a suspend function's result is its Continuation's type.
 */
@RestController
class ReportController {

    @GetMapping("/reports")
    fun reports(): Flow<Report> = flowOf(Report("daily"))

    @GetMapping("/report")
    suspend fun report(): Report = Report("daily")
}
