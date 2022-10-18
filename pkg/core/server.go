package core

import (
	"encoding/json"
	"fmt"
	"image"
	"image/png"
	"net/http"
	"os"
	"sort"
	"strconv"

	"github.com/jhump/protoreflect/dynamic"
	"golang.org/x/image/draw"
)

type Achievement struct {
	ID   uint32
	Data []byte
}

type Avatar struct {
	ID   uint32
	Data []byte
}

type Entity struct {
	ID   uint32
	Data []byte
}

type Player struct {
	ID   uint32
	Data []byte
}

type Item struct {
	ID   uint32
	Data []byte
}

func (s *Service) HandleMessage(command string, message *dynamic.Message) {
	switch command {
	case "AchievementAllDataNotify", "AchievementUpdateNotify":
		items := []*Achievement{}
		for _, v := range message.GetFieldByName("achievement_list").([]any) {
			v := v.(*dynamic.Message)
			item := &Achievement{ID: v.GetFieldByName("id").(uint32)}
			data, _ := json.Marshal(v)
			item.Data = data
			items = append(items, item)
		}
		s.UpdateAchievement(items...)
	case "AvatarDataNotify":
		items := []*Avatar{}
		for _, v := range message.GetFieldByName("avatar_list").([]any) {
			v := v.(*dynamic.Message)
			item := &Avatar{ID: uint32(v.GetFieldByName("guid").(uint64))}
			data, _ := json.Marshal(v)
			item.Data = data
			items = append(items, item)
		}
		s.UpdateAvatar(items...)
	case "SceneEntityAppearNotify":
		items := []*Entity{}
		for _, v := range message.GetFieldByName("entity_list").([]any) {
			v := v.(*dynamic.Message)
			item := &Entity{ID: v.GetFieldByName("entity_id").(uint32)}
			data, _ := json.Marshal(v)
			item.Data = data
			items = append(items, item)
		}
		s.UpdateEntity(items...)
	case "SceneEntityDisappearNotify":
		ids := []uint32{}
		for _, v := range message.GetFieldByName("entity_list").([]any) {
			ids = append(ids, v.(uint32))
		}
		s.DeleteEntity(ids...)
	case "ScenePlayerLocationNotify":
		items := []*Player{}
		for _, v := range message.GetFieldByName("player_loc_list").([]any) {
			v := v.(*dynamic.Message)
			item := &Player{ID: v.GetFieldByName("uid").(uint32)}
			data, _ := json.Marshal(v)
			item.Data = data
			items = append(items, item)
		}
		s.UpdatePlayer(items...)
	case "PlayerStoreNotify", "StoreItemChangeNotify":
		items := []*Item{}
		for _, v := range message.GetFieldByName("item_list").([]any) {
			v := v.(*dynamic.Message)
			item := &Item{ID: uint32(v.GetFieldByName("guid").(uint64))}
			data, _ := json.Marshal(v)
			item.Data = data
			items = append(items, item)
		}
		s.UpdateItem(items...)
	}
}

func (s *Service) UpdateAchievement(items ...*Achievement) {
	s.mutex.Lock()
	for _, item := range items {
		s.achievementMap[item.ID] = item
	}
	s.mutex.Unlock()
}

func (s *Service) SelectAchievement() []*Achievement {
	s.mutex.RLock()
	items := []*Achievement{}
	for _, item := range s.achievementMap {
		items = append(items, item)
	}
	s.mutex.RUnlock()
	sort.Slice(items, func(i, j int) bool {
		return items[i].ID < items[j].ID
	})
	return items
}

func (s *Service) UpdateAvatar(items ...*Avatar) {
	s.mutex.Lock()
	for _, item := range items {
		s.avatarMap[item.ID] = item
	}
	s.mutex.Unlock()
}

func (s *Service) SelectAvatar() []*Avatar {
	s.mutex.RLock()
	items := []*Avatar{}
	for _, item := range s.avatarMap {
		items = append(items, item)
	}
	s.mutex.RUnlock()
	sort.Slice(items, func(i, j int) bool {
		return items[i].ID < items[j].ID
	})
	return items
}

func (s *Service) UpdateEntity(items ...*Entity) {
	s.mutex.Lock()
	for _, item := range items {
		s.entityMap[item.ID] = item
	}
	s.mutex.Unlock()
}

func (s *Service) DeleteEntity(ids ...uint32) {
	s.mutex.Lock()
	for _, id := range ids {
		delete(s.entityMap, id)
	}
	s.mutex.Unlock()
}

func (s *Service) SelectEntity() []*Entity {
	s.mutex.RLock()
	items := []*Entity{}
	for _, item := range s.entityMap {
		items = append(items, item)
	}
	s.mutex.RUnlock()
	sort.Slice(items, func(i, j int) bool {
		return items[i].ID < items[j].ID
	})
	return items
}

func (s *Service) UpdatePlayer(items ...*Player) {
	s.mutex.Lock()
	for _, item := range items {
		s.playerMap[item.ID] = item
	}
	s.mutex.Unlock()
}

func (s *Service) SelectPlayer() []*Player {
	s.mutex.RLock()
	items := []*Player{}
	for _, item := range s.playerMap {
		items = append(items, item)
	}
	s.mutex.RUnlock()
	sort.Slice(items, func(i, j int) bool {
		return items[i].ID < items[j].ID
	})
	return items
}

func (s *Service) UpdateItem(items ...*Item) {
	s.mutex.Lock()
	for _, item := range items {
		s.itemMap[item.ID] = item
	}
	s.mutex.Unlock()
}

func (s *Service) DeleteItem(ids ...uint32) {
	s.mutex.Lock()
	for _, id := range ids {
		delete(s.itemMap, id)
	}
	s.mutex.Unlock()
}

func (s *Service) SelectItem() []*Item {
	s.mutex.RLock()
	items := []*Item{}
	for _, item := range s.itemMap {
		items = append(items, item)
	}
	s.mutex.RUnlock()
	sort.Slice(items, func(i, j int) bool {
		return items[i].ID < items[j].ID
	})
	return items
}

func (s *Service) start() error {
	s.achievementMap = make(map[uint32]*Achievement)
	s.avatarMap = make(map[uint32]*Avatar)
	s.entityMap = make(map[uint32]*Entity)
	s.playerMap = make(map[uint32]*Player)
	s.itemMap = make(map[uint32]*Item)

	s.teyvatMap = make(map[uint32][][]image.Image)
	scene := uint32(3)
	for i := 0; i < 4; i++ {
		s.teyvatMap[scene] = append(s.teyvatMap[scene], []image.Image{})
		for j := 0; j < 3; j++ {
			f, _ := os.OpenFile(fmt.Sprintf("data/static/tile/3/2_%d_%d.png", i, j), os.O_RDONLY, 0)
			img, _, _ := image.Decode(f)
			s.teyvatMap[scene][i] = append(s.teyvatMap[scene][i], img)
			f.Close()
		}
	}

	http.HandleFunc("/api/achievement", func(w http.ResponseWriter, r *http.Request) {
		items := s.SelectAchievement()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("["))
		for i, item := range items {
			w.Write([]byte(fmt.Sprintf("{\"id\":%d,\"data\":%s}", item.ID, item.Data)))
			if i < len(items)-1 {
				w.Write([]byte(","))
			}
		}
		w.Write([]byte("]"))
	})
	http.HandleFunc("/api/avatar", func(w http.ResponseWriter, r *http.Request) {
		items := s.SelectAvatar()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("["))
		for i, item := range items {
			w.Write([]byte(fmt.Sprintf("{\"id\":%d,\"data\":%s}", item.ID, item.Data)))
			if i < len(items)-1 {
				w.Write([]byte(","))
			}
		}
		w.Write([]byte("]"))
	})
	http.HandleFunc("/api/entity", func(w http.ResponseWriter, r *http.Request) {
		items := s.SelectEntity()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("["))
		for i, item := range items {
			w.Write([]byte(fmt.Sprintf("{\"id\":%d,\"data\":%s}", item.ID, item.Data)))
			if i < len(items)-1 {
				w.Write([]byte(","))
			}
		}
		w.Write([]byte("]"))
	})
	http.HandleFunc("/api/player", func(w http.ResponseWriter, r *http.Request) {
		items := s.SelectPlayer()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("["))
		for i, item := range items {
			w.Write([]byte(fmt.Sprintf("{\"id\":%d,\"data\":%s}", item.ID, item.Data)))
			if i < len(items)-1 {
				w.Write([]byte(","))
			}
		}
		w.Write([]byte("]"))
	})
	http.HandleFunc("/api/item", func(w http.ResponseWriter, r *http.Request) {
		items := s.SelectItem()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("["))
		for i, item := range items {
			w.Write([]byte(fmt.Sprintf("{\"id\":%d,\"data\":%s}", item.ID, item.Data)))
			if i < len(items)-1 {
				w.Write([]byte(","))
			}
		}
		w.Write([]byte("]"))
	})
	http.HandleFunc("/api/tile", func(w http.ResponseWriter, r *http.Request) {
		scene, _ := strconv.Atoi(r.URL.Query().Get("scene"))
		x, _ := strconv.Atoi(r.URL.Query().Get("x"))
		y, _ := strconv.Atoi(r.URL.Query().Get("y"))
		z, _ := strconv.Atoi(r.URL.Query().Get("z"))
		zz := 1 << (z - 2)
		i, j := x/zz, y/zz
		xx, yy := x%zz, y%zz
		dst := image.NewRGBA(image.Rect(0, 0, 256, 256))
		if scene == 3 && i < 4 && j < 3 {
			src := s.teyvatMap[uint32(scene)][i][j]
			rec := src.Bounds()
			rec = image.Rect(xx*rec.Dx()/zz, yy*rec.Dy()/zz, (xx+1)*rec.Dx()/zz, (yy+1)*rec.Dy()/zz)
			draw.NearestNeighbor.Scale(dst, dst.Rect, src, rec, draw.Over, nil)
		}
		w.Header().Set("Content-Type", "image/png")
		png.Encode(w, dst)
	})
	http.HandleFunc("/achievement/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "data/template/achievement/index.html")
	})
	http.HandleFunc("/avatar/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "data/template/avatar/index.html")
	})
	http.HandleFunc("/entity/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "data/template/entity/index.html")
	})
	http.HandleFunc("/player/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "data/template/player/index.html")
	})
	http.HandleFunc("/item/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "data/template/item/index.html")
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "data/template/index.html")
	})
	return http.ListenAndServe(":8080", nil)
}
