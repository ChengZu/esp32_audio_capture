idf_component_register(SRCS "main.c" "i2s_std.c" "softap.c" "station.c" "cJSON.c" "http_server.c" "reset_task.c" "ota.c" 
                    EMBED_FILES "boot.wav" "index.html" "favicon.ico" "connect-wifi.html" "play-audio.html" "reset.html" "styles.css"
                    INCLUDE_DIRS ".")
