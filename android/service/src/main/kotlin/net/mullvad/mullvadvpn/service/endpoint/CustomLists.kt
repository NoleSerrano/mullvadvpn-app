package net.mullvad.mullvadvpn.service.endpoint

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.filterIsInstance
import kotlinx.coroutines.launch
import net.mullvad.mullvadvpn.lib.ipc.Event
import net.mullvad.mullvadvpn.lib.ipc.Request

class CustomLists(
    private val endpoint: ServiceEndpoint,
    dispatcher: CoroutineDispatcher = Dispatchers.IO
) {
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + dispatcher)
    private val daemon
        get() = endpoint.intermittentDaemon

    init {
        scope.launch {
            endpoint.dispatcher.parsedMessages
                .filterIsInstance<Request.CreateCustomList>()
                .collect { createCustomList(it.name) }
        }

        scope.launch {
            endpoint.dispatcher.parsedMessages
                .filterIsInstance<Request.DeleteCustomList>()
                .collect { daemon.await().deleteCustomList(it.id) }
        }

        scope.launch {
            endpoint.dispatcher.parsedMessages
                .filterIsInstance<Request.UpdateCustomList>()
                .collect { daemon.await().updateCustomList(it.customList) }
        }
    }

    private suspend fun createCustomList(name: String) {
        val result = daemon.await().createCustomList(name)
        endpoint.sendEvent(Event.CreateCustomListResult(result))
    }

    fun onDestroy() {
        scope.cancel()
    }
}
