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

import java.util.Collection;


public interface ItemDAO {

  public MusicItem get(Long id);

  public Collection<MusicItem> getAll();

  public Collection<MusicItem> searchByArtistTitle(String keyword);
}
