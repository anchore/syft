{application, 'rabbit', [
	{description, "RabbitMQ"},
	{vsn, "3.12.10"},
	{id, "v3.12.9-9-g1f61ca8"},
	{modules, ['amqqueue','background_gc']},
	{optional_applications, []},
	{env, [
	    {memory_monitor_interval, 2500},
	    {disk_free_limit, 50000000}, %% 50MB
	    {msg_store_index_module, rabbit_msg_store_ets_index},
	    {backing_queue_module, rabbit_variable_queue},
	    %% 0 ("no limit") would make a better default, but that
	    %% breaks the QPid Java client
	    {frame_max, 131072},
	    %% see rabbitmq-server#1593
	    {channel_max, 2047}
	  ]}
]}.