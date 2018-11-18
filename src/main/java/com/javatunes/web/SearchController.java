/*
 * This code is sample code, provided as-is, and we make no
 * warranties as to its correctness or suitability for
 * any purpose.
 *
 * We hope that it's useful to you.  Enjoy.
 * Copyright 2006-12 LearningPatterns Inc.
 */
 
package com.javatunes.web;

import com.javatunes.catalog.Catalog;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import java.util.ArrayList;
import java.util.Collection;

@Controller
@RequestMapping("/search")
public class SearchController {
    @Autowired
    Catalog cat;

    // Optional - Method to add reference data into model
    @ModelAttribute("artists")
    public Collection<String> populateArtists() {
        ArrayList<String> artists = new ArrayList<String>();
        artists.add("");
        artists.add("Annie Lennox");
        artists.add("Sting");
        artists.add("Seal");
        return artists;
    }

    // Handler method to forward to the search form
    @RequestMapping(method = RequestMethod.GET)
    public String get(@ModelAttribute("search") Search search) {
        search.setKeyword("Diva");
        return "searchForm";
    }

    // Handler method to process the search form submission
    // Uses optional searchArtist functionality
    @RequestMapping(method = RequestMethod.POST)
    public String processSearch(@ModelAttribute("search") Search search) {
        System.out.println("SearchController.processSearch()");
        String searchFor = search.getKeyword();
        if (search.getArtist()!=null && search.getArtist().length()>0) {
            searchFor = search.getArtist();
        }
        search.setResults(cat.findByKeyword(searchFor));
        return "searchResults";
    }
}