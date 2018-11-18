/*
 * This code is sample code, provided as-is, and we make no
 * warranties as to its correctness or suitablity for
 * any purpose.
 *
 * We hope that it's useful to you.  Enjoy.
 * Copyright 2006-7 LearningPatterns Inc.
 */

package com.javatunes.util;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.math.BigDecimal;

public class MusicItem
implements java.io.Serializable
{
   private static final long serialVersionUID = 1L;
   
   // properties
   private Long       m_id;
   private String     m_num;
   private String     m_title;
   private String     m_artist;
   private Date       m_releaseDate;
   private BigDecimal m_listPrice;
   private BigDecimal m_price;
   
   SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd");

   public MusicItem() { }

   public MusicItem(Long id)
   {
      this.setId(id);
   }


   public MusicItem(Long id, String num, String title, String artist,
                    Date releaseDate, BigDecimal listPrice, BigDecimal price)
   {
	  this.setId(id);
      this.setNum(num);
      this.setTitle(title);
      this.setArtist(artist);
      this.setReleaseDate(releaseDate);
      this.setListPrice(listPrice);
      this.setPrice(price);
   }

   public Long getId() { return m_id; }
   public String getNum() { return m_num; }
   public String getTitle() { return m_title; }
   public String getArtist() { return m_artist; }
   public Date getReleaseDate() { return m_releaseDate; }
   public BigDecimal getListPrice() { return m_listPrice; }
   public BigDecimal getPrice() { return m_price; }

   public void setId(Long id) { m_id = id; }
   public void setNum(String num) { m_num = num; }
   public void setTitle(String title) { m_title = title; }
   public void setArtist(String artist) { m_artist = artist; }
   public void setReleaseDate(Date releaseDate) { m_releaseDate = releaseDate; }
   public void setReleaseDateString(String releaseDateString) { 
	   try {  
		   m_releaseDate = df.parse(releaseDateString);
	   } catch (ParseException e) {	e.printStackTrace(); }
   }
   public void setListPrice(BigDecimal listPrice) { m_listPrice = listPrice; }
   public void setPrice(BigDecimal price) { m_price = price; }

   // override Object.equals
   public boolean equals(Object compare)
   {
      boolean result = false;
      MusicItem other = null;

      if (compare instanceof MusicItem)
      {
         // cast to MusicItem
         other = (MusicItem) compare;

         // if all the ids are equal, the objects are equal
         result = other.getId().equals(this.getId()) ;
      }
      return result;
   }

   // override Object.toString
   public String toString()
   {
      return this.getClass().getName() +
         ": id=" + this.getId() +
         ": num=" + this.getNum() +
         " title=" + this.getTitle() +
         " artist=" + this.getArtist() +
         " releaseDate=" + this.getReleaseDate() +
         " listPrice=" + this.getListPrice() +
         " price=" + this.getPrice();
   }
}
