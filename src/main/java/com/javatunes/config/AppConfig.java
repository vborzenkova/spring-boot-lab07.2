package com.javatunes.config;

import com.javatunes.catalog.InMemoryItemDAO;
import com.javatunes.catalog.ItemDAO;
import com.javatunes.catalog.JavaTunesCatalog;
import com.javatunes.util.MusicItem;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;

import java.util.ArrayList;

@Configuration
@ImportResource("classpath:inMemoryItemDAO.xml")
public class AppConfig {
    @Bean("javatunesCatalog")
    JavaTunesCatalog catalog(ItemDAO inMemoryItemDAO){
        JavaTunesCatalog cat = new JavaTunesCatalog(inMemoryItemDAO);
        cat.setMaxSearchResults(20);
        return cat;
    }


}
