package fixtures.kotlinsuspend

import org.springframework.context.annotation.Configuration
import org.springframework.kafka.annotation.KafkaListener
import org.springframework.scheduling.annotation.EnableScheduling
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Component

/**
 * Suspend functions in open (Spring) classes: Kotlin copies their annotations onto a static f$suspendImpl body.
 */
@Configuration
@EnableScheduling
class SchedulingConfig

@Component
class Jobs {

    @Scheduled(fixedRate = 60000)
    suspend fun tick() {
    }
}

@Component
class OrderListener {

    @KafkaListener(topics = ["orders"])
    suspend fun onOrder(order: String) {
    }
}
