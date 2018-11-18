/*
 * This code is sample code, provided as-is, and we make no
 * warranties as to its correctness or suitability for
 * any purpose.
 *
 * We hope that it's useful to you.  Enjoy.
 * Copyright 2006-12 LearningPatterns Inc.
 */


package com.javatunes.catalog;

import com.javatunes.util.MusicItem;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Component;

import javax.annotation.security.RolesAllowed;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

/**
 * This class is a simple bean that emulates the search of some catalog.
 * We do this so we don't need a database at this early stage of the course.  This will be
 * replaced with a persistent entity that goes to a database in a later lab.
 */

public class InMemoryItemDAO implements ItemDAO {

	   // catalog of MusicItem objects
	   private Collection<MusicItem> catalog;
	   

public InMemoryItemDAO(Collection<MusicItem> catalogIn) {
		catalog = catalogIn;
	   }

public InMemoryItemDAO(){};

    // searches catalog by ID
   public MusicItem get(Long id)
   {
      // declare return value
      MusicItem result = null;

      // iterate through the catalog, looking for an ID match
      for (MusicItem item : catalog) {
         if (item.getId().equals(id))
         {
            result = item;    // assign to return value
            break;            // found it - stop looping
         }
      }
      return result;
   }
   /* Annotation Secured worked only with prefix ROLE_ even though roles are declared without prefix ROLE_**/
  //@Secured("ROLE_ADMIN")

   /*You can try this with JSR-250 annotations**/
   //@RolesAllowed("ADMIN")

   /* This is a new version of Secured annotation in Spring**/
   @PreAuthorize("hasRole('ADMIN')")
   public Collection<MusicItem> searchByArtistTitle(String keyword)
   {
      // declare return value
      Collection<MusicItem> result = new ArrayList<MusicItem>();

      // remove case sensitivity
      keyword = keyword.toLowerCase();

      // iterate through the catalog, looking for a keyword match
      for (MusicItem item : catalog) {
         if (item.getTitle().toLowerCase().indexOf(keyword) != -1 ||
             item.getArtist().toLowerCase().indexOf(keyword) != -1)
         {
            result.add(item);
         }
      }
      return result;
   }
   
   public Collection<MusicItem> getAll() {
	   return Collections.unmodifiableCollection(catalog);
   }

}
